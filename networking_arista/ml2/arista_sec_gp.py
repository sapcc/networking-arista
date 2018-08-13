# Copyright (c) 2016 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import itertools
import json
import math
import os
import re
import requests
import six
import socket

from collections import defaultdict
from copy import copy
from eventlet.greenpool import GreenPool as Pool
from hashlib import sha1
from httplib import HTTPException

from netaddr import EUI
from netaddr import IPNetwork
from netaddr import IPSet
from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils.importutils import try_import

from networking_arista._i18n import _
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import util

dogstatsd = try_import('datadog.dogstatsd')

if not dogstatsd or os.getenv('STATSD_MOCK', False):
    from mock import Mock

    STATS = Mock()
else:
    STATS = dogstatsd.DogStatsd(host=os.getenv('STATSD_HOST', 'localhost'),
                                port=int(os.getenv('STATSD_PORT', 9125)),
                                namespace=os.getenv('STATSD_PREFIX',
                                                    'openstack')
                                )

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')

# Note 'None,null' means default rule - i.e. deny everything
SUPPORTED_SG_PROTOCOLS = ['tcp', 'udp', 'icmp', 'dhcp', None]
SUPPORTED_SG_ETHERTYPES = ['IPv4']

DIRECTIONS = ['ingress', 'egress']
INTERFACE_DIRECTIONS = ['configuredEgressIntfs', 'configuredIngressIntfs']

_ANY_IP_V4 = IPNetwork('0.0.0.0/0')

_ANY_NET = {
    'IPv4': _ANY_IP_V4,
    'IPv6': IPNetwork('::/0')
}

CONF = cfg.CONF

memoize = cfg.BoolOpt('memoize', default=True)

# Do not expire by default, as we only store "fixed" values
# This ensures that we do not need to connect to all the switches to
# get the association between system_id (EUI), and the ip
memoize_time = cfg.IntOpt('memoize_time', default=0)
CONF.register_opts([memoize, memoize_time], 'ml2_arista')

cache.configure(CONF)
arista_cache_region = cache.create_region()
MEMOIZE = cache.get_memoization_decorator(
    CONF, arista_cache_region, 'ml2_arista')

# Load config file here

cache.configure_cache_region(CONF, arista_cache_region)

acl_cmd = {
    # For a rule 0: protocol, 1: cidr, 2: from_port, 3: to_port, 4: flags
    'acl': {'create': ['ip access-list {0}'],
            'tcp_established': ['permit tcp any any established'],
            'in_rule': ['permit {0} {1} any range {2} {3} {4}'],
            'in_rule_reverse': ['permit {0} any range {2} {3} {1}'],
            'out_rule': ['permit {0} any {1} range {2} {3}'],
            'out_rule_tcp': ['permit {0} any {1} range {2} {3} {4}'],
            'out_rule_reverse': ['permit {0} {1} range {2} {3} any {4}'],
            'in_dhcp_rule': ['permit udp {1} eq {2} any eq {3}'],
            'out_dhcp_rule': ['permit udp any eq {3} {1} eq {2}'],
            'in_icmp_custom1': ['permit icmp {0} any {1}'],
            'out_icmp_custom1': ['permit icmp any {0} {1}'],
            'in_icmp_custom2': ['permit icmp {0} any {1} {2}'],
            'out_icmp_custom2': ['permit icmp any {0} {1} {2}'],
            'in_icmp_custom3': ['permit icmp {0} any'],
            'out_icmp_custom3': ['permit icmp any {0}'],
            'default': [],
            'delete_acl': ['no ip access-list {0}'],
            'del_in_icmp_custom1': ['ip access-list {0}',
                                    'no permit icmp {1} any {2}',
                                    'exit'],
            'del_out_icmp_custom1': ['ip access-list {0}',
                                     'no permit icmp any {1} {2}',
                                     'exit'],
            'del_in_icmp_custom2': ['ip access-list {0}',
                                    'no permit icmp {1} any {2} {3}',
                                    'exit'],
            'del_out_icmp_custom2': ['ip access-list {0}',
                                     'no permit icmp any {1} {2} {3}',
                                     'exit'],
            'del_in_acl_rule': ['ip access-list {0}',
                                'no permit {1} {2} any range {3} {4}',
                                'exit'],
            'del_out_acl_rule': ['ip access-list {0}',
                                 'no permit {1} any {2} range {3} {4}',
                                 'exit']},

    'apply': {'ingress': ['interface {0}',
                          'ip access-group {1} out',
                          'exit'],
              'egress': ['interface {0}',
                         'ip access-group {1} in',
                         'exit'],
              'rm_ingress': ['interface {0}',
                             'no ip access-group {1} out',
                             'exit'],
              'rm_egress': ['interface {0}',
                            'no ip access-group {1} in',
                            'exit']}}

_COMMAND_PARSE_PATTERN = {
    # This compacts typical setups by using other security groups as
    # rule
    # e.g. Match 'permit tcp host 10.180.1.2 any range 10000 10000 syn'
    False: {
        'ingress': re.compile(
            r"^permit (?P<proto>udp|tcp) "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any) "
            r"any "
            r"range (?P<port_min>\w+) (?P<port_max>\w+)(?: syn)?"
        ),
        'egress': re.compile(
            r"^permit (?P<proto>udp|tcp) "
            r"any "
            r"range (?P<port_min>\w+) (?P<port_max>\w+) "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?: syn)?"
        ),
    },
    True: {
        'ingress': re.compile(
            r"^permit (?P<proto>icmp) "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any) "
            r"any"
            r"(?: (?P<port_min>\w+))?"
            r"(?: (?P<port_max>\w+))?$"
        ),
        'egress': re.compile(
            r"^permit (?P<proto>icmp) "
            r"any "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?: (?P<port_min>\w+))?"
            r"(?: (?P<port_max>\w+))?$"
        ),
    }
}

_COMMAND_FORMAT_PATTERN = {
    False: {
        'ingress':
            'permit {proto} {host} any range {port_min} {port_max} {flags}',
        'egress':
            'permit {proto} any {host} range {port_min} {port_max} {flags}'
    },
    True: {
        'ingress':
            'permit {proto} {host} any {port_min} {port_max}',
        'egress':
            'permit {proto} any {host} {port_min} {port_max}'
    }
}


class AristaSwitchRPCMixin(object):
    _SERVER_BY_ID = dict()
    _SERVER_BY_IP = dict()
    _INTERFACE_MEMBERSHIP = defaultdict(dict)

    def __init__(self, *args, **kwargs):
        super(AristaSwitchRPCMixin, self).__init__()
        self._conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self._verify = cfg.CONF.ml2_arista.verify_ssl
        self._session = kwargs.get('session') or util.make_http_session()

    def _get_interface_membership(self, server, ports):
        ifm = self._INTERFACE_MEMBERSHIP[server]
        missing = []
        result = dict()
        for port in ports:
            if port in ifm:
                result[port] = ifm[port]
            else:
                missing.append(port)

        if not missing:
            return result

        ret = server(["show interfaces " + ",".join(missing)])
        if ret and ret[0]:
            for port, v in six.iteritems(ret[0]['interfaces']):
                if not v:
                    continue
                pc = None
                membership = v.get('interfaceMembership')
                if membership:
                    pc = membership.rsplit(' ')[-1]
                ifm[port] = pc
                result[port] = pc
        return result

    def _send_eapi_req(self, url, cmds):
        # This method handles all EAPI requests (using the requests library)
        # and returns either None or response.json()['result'] from the EAPI
        # request.
        #
        # Exceptions related to failures in connecting/ timeouts are caught
        # here and logged. Other unexpected exceptions are logged and raised

        params = {
            'timestamps': 'false',
            'format': 'json',
            'version': 1,
            'cmds': cmds,
        }

        data = {
            'id': 'Arista ML2 driver',
            'method': 'runCmds',
            'jsonrpc': '2.0',
            'params': params,
        }

        try:
            LOG.debug("Sending %s", cmds)
            response = self._session.post(
                url,
                verify=self._verify,
                timeout=self._conn_timeout,
                json=data)
            try:
                return response.json()['result']
            except KeyError:
                msg = "Unexpected EAPI error"
                LOG.info(msg)
                raise arista_exc.AristaRpcError(msg=msg)
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out while trying to connect to %(url)s') %
                   {'url': url})
            LOG.warning(msg)
            return None
        except requests.exceptions.ReadTimeout:
            msg = (_('Timed out while reading from %(url)s') %
                   {'url': url})
            LOG.warning(msg)
            return None
        except requests.exceptions.ConnectionError as e:
            msg = (_('Error while trying to connect to %(url)s'
                     'due to %(reason)s') %
                   {'url': url, 'reason': e})
            LOG.warning(msg)
            return None
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(url)s') %
                   {'url': url})
            LOG.warning(msg)
            return None
        except ValueError:
            LOG.info("Ignoring invalid JSON response")
            return None
        except Exception as error:
            msg = six.text_type(error)
            LOG.warning(msg)
            raise

    def _validate_config(self, reason=''):
        if len(cfg.CONF.ml2_arista.get('switch_info')) < 1:
            msg = _('Required option - %s, '
                    'at least one switch must be specified ') % reason
            LOG.exception(msg)
            raise arista_exc.AristaConfigError(msg=msg)

    def _maintain_connections(self):
        switches = []

        for s in cfg.CONF.ml2_arista.switch_info:
            switch_ip, switch_user, switch_pass = s.split(":")
            if switch_ip not in self._SERVER_BY_IP:
                switches.append((switch_ip, switch_user, switch_pass))

        if not switches:
            return

        server_by_ip = copy(self._SERVER_BY_IP)
        server_by_id = copy(self._SERVER_BY_ID)

        pool = Pool()
        items = [s for s in pool.starmap(self._connect_to_switch, switches)
                 if s]

        for switch_ip, system_id, server in items:
            server_by_ip[switch_ip] = server
            server_by_id[system_id] = server

        AristaSwitchRPCMixin._SERVER_BY_ID = server_by_id
        AristaSwitchRPCMixin._SERVER_BY_IP = server_by_ip

    def _connect_to_switch(self, switch_ip, switch_user, switch_pass):
        if switch_pass == "''":
            switch_pass = ''
        eapi_server_url = ('https://%s:%s@%s/command-api' %
                           (switch_user, switch_pass, switch_ip))
        try:
            def server(cmds):
                return self._send_eapi_req(eapi_server_url, cmds)

            @MEMOIZE
            def get_lldp_info(_):
                try:
                    ret = server(['show lldp local-info management 1'])
                    return EUI(ret[0]['chassisId'])
                except (IndexError, TypeError, KeyError):
                    return None

            system_id = get_lldp_info(switch_ip)
            if not system_id:
                get_lldp_info.invalidate(switch_ip)
                LOG.warn("Could not connect to server %s",
                         switch_ip)
                return
            else:
                return switch_ip, system_id, server
        except (socket.error, HTTPException) as e:
            LOG.warn("Could not connect to server %s due to %s",
                     switch_ip, e)

    @property
    def _server_by_id(self):
        return self._SERVER_BY_ID

    def _get_server_by_id(self, switch_id):
        return switch_id and self._SERVER_BY_ID.get(EUI(switch_id))

    def _get_server_by_ip(self, switch_ip):
        return switch_ip and self._SERVER_BY_IP.get(switch_ip)

    def _get_server(self, switch_info=None, switch_id=None):
        server = (self._get_server_by_id(switch_id)
                  or self._get_server_by_ip(switch_info))

        if server:
            return server

        self._maintain_connections()

        return (self._get_server_by_id(switch_id)
                or self._get_server_by_ip(switch_info))


class AristaSecGroupSwitchDriver(AristaSwitchRPCMixin):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """

    def __init__(self, neutron_db, http_session=None):
        super(AristaSecGroupSwitchDriver, self).__init__(
            http_session=http_session)
        self._ndb = neutron_db
        self.sg_enabled = cfg.CONF.ml2_arista.get('sec_group_support')
        if not self.sg_enabled:
            return

        self._validate_config(_('when "sec_group_support" is enabled'))
        self._statsd = STATS
        self.max_rules = cfg.CONF.ml2_arista.get('lossy_consolidation_limit')

        self._protocol_table = {
            num: name[8:] for name, num in vars(socket).items()
            if name.startswith("IPPROTO")
        }
        self.aclCreateDict = acl_cmd['acl']
        self.aclApplyDict = acl_cmd['apply']

    def _get_port_name(self, port, protocol=None):
        try:
            return socket.getservbyport(port, protocol)
        except socket.error:
            return port

    def _create_acl_on_eos(self, in_cmds, out_cmds, protocol, cidr,
                           from_port, to_port, direction):
        """Creates an ACL on Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """

        if cidr:
            if cidr == 'any' or cidr.endswith('/0'):
                cidr = 'any'
            elif cidr.endswith('/32'):
                cidr = 'host ' + cidr[:-3]
            elif '/' not in cidr:
                cidr = 'host ' + cidr

        if protocol == 'icmp':
            # ICMP rules require special processing
            if from_port is None and to_port is None:
                rule = 'icmp_custom3'
            elif from_port is not None and to_port is not None:
                rule = 'icmp_custom2'
            elif from_port is not None and to_port is None:
                rule = 'icmp_custom1'
            else:
                msg = _('Invalid ICMP rule specified')
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)
            rule_type = 'in'
            cmds = in_cmds
            if direction == 'egress':
                rule_type = 'out'
                cmds = out_cmds
            final_rule = rule_type + '_' + rule
            acl_dict = self.aclCreateDict[final_rule]

            # None port is problematic - should be replaced with 0
            if not from_port:
                from_port = 0
            if not to_port:
                to_port = 0

            for c in acl_dict:
                if rule == 'icmp_custom2':
                    cmds.append(c.format(cidr, from_port, to_port))
                else:
                    cmds.append(c.format(cidr, from_port))
            return in_cmds, out_cmds
        elif protocol == 'dhcp':
            # Not really a layer2 protocol

            for c in self.aclCreateDict['in_dhcp_rule']:
                in_cmds.append(c.format(protocol, cidr, from_port, to_port))

            for c in self.aclCreateDict['out_dhcp_rule']:
                out_cmds.append(c.format(protocol, cidr, from_port, to_port))

            return in_cmds, out_cmds
        else:
            # Non ICMP rules processing here
            flags = ''
            if direction == 'egress':
                if protocol == 'tcp':
                    flags = 'syn'
                    out_rule = self.aclCreateDict['out_rule_tcp']
                    in_rule = []
                else:
                    flags = 'range 32768 65535'
                    out_rule = self.aclCreateDict['out_rule']
                    in_rule = self.aclCreateDict['out_rule_reverse']
            else:
                in_rule = self.aclCreateDict['in_rule']
                if protocol == 'tcp':
                    flags = 'syn'
                    out_rule = []
                else:
                    out_rule = self.aclCreateDict['in_rule_reverse']

            for c in in_rule:
                in_cmds.append(c.format(protocol, cidr, from_port, to_port,
                                        flags).strip())

            for c in out_rule:
                out_cmds.append(c.format(protocol, cidr, from_port, to_port,
                                         flags).strip())

            return in_cmds, out_cmds

    def _delete_acl_from_eos(self, name, server):
        """deletes an ACL from Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        for c in self.aclCreateDict['delete_acl']:
            cmds.append(c.format(name))

        self._run_openstack_sg_cmds(cmds, server)

    def _delete_acl_rule_from_eos(self, name,
                                  protocol, cidr,
                                  from_port, to_port,
                                  direction, server):
        """deletes an ACL from Arista HW Device.

        :param name: Name for the ACL
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        if protocol == 'icmp':
            # ICMP rules require special processing
            if from_port and to_port or (not from_port and not to_port):
                rule = 'icmp_custom2'
            elif from_port and not to_port:
                rule = 'icmp_custom1'
            else:
                msg = _('Invalid ICMP rule specified')
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)
            rule_type = 'del_in'
            if direction == 'egress':
                rule_type = 'del_out'
            final_rule = rule_type + '_' + rule
            acl_dict = self.aclCreateDict[final_rule]

            # None port is problematic - should be replaced with 0
            if not from_port:
                from_port = 0
            if not to_port:
                to_port = 0

            for c in acl_dict:
                if rule == 'icmp_custom2':
                    cmds.append(c.format(name, cidr, from_port, to_port))
                else:
                    cmds.append(c.format(name, cidr, from_port))

        else:
            acl_dict = self.aclCreateDict['del_in_acl_rule']
            if direction == 'egress':
                acl_dict = self.aclCreateDict['del_out_acl_rule']

            for c in acl_dict:
                cmds.append(c.format(name, protocol, cidr,
                                     from_port, to_port))

        self._run_openstack_sg_cmds(cmds, server)

    def _apply_acl_on_eos(self, port_id, name, direction, server,
                          accumulator=None):
        """Creates an ACL on Arista HW Device.

        :param port_id: The port where the ACL needs to be applied
        :param name: Name for the ACL
        :param direction: must contain "ingress" or "egress"
        :param server: Server endpoint on the Arista switch to be configured
        """
        if accumulator is None:
            cmds = []
        else:
            cmds = accumulator

        for c in self.aclApplyDict[direction]:
            cmds.append(c.format(port_id, name))

        if not accumulator:
            self._run_openstack_sg_cmds(cmds, server)

    def _remove_acl_from_eos(self, port_id, name, direction, server):
        """Remove an ACL from a port on Arista HW Device.

        :param port_id: The port where the ACL needs to be applied
        :param name: Name for the ACL
        :param direction: must contain "ingress" or "egress"
        :param server: Server endpoint on the Arista switch to be configured
        """
        cmds = []

        if direction == 'egress':
            acl_cmd = self.aclApplyDict['rm_egress']
        else:
            acl_cmd = self.aclApplyDict['rm_ingress']

        for c in acl_cmd:
            cmds.append(c.format(port_id, name))

        self._run_openstack_sg_cmds(cmds, server)

    def _create_acl_rule(self, context, in_cmds, out_cmds, sgr,
                         security_group_ips=None):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Only deal with valid protocols - skip the rest
        if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
            return in_cmds, out_cmds

        if sgr['ethertype'] is not None \
                and sgr['ethertype'] not in SUPPORTED_SG_ETHERTYPES:
            return in_cmds, out_cmds

        if sgr['protocol'] is None:
            protocols = SUPPORTED_SG_PROTOCOLS[0:3]
        else:
            protocols = [sgr['protocol']]

        remote_ips = ['any']
        remote_ip_prefix = sgr['remote_ip_prefix']
        remote_group_id = sgr['remote_group_id']

        if remote_ip_prefix:
            remote_ips = [remote_ip_prefix]
        elif remote_group_id:
            security_group_ips = security_group_ips or {}
            if remote_group_id not in security_group_ips:
                fetched = self._ndb._select_ips_for_remote_group(
                    context, [remote_group_id])
                security_group_ips.update(fetched)

            remote_ips = security_group_ips[remote_group_id]

        for remote_ip in remote_ips:
            for protocol in protocols:
                min_port = sgr['port_range_min']
                if protocol != 'icmp' and not min_port:
                    min_port = 0

                max_port = sgr['port_range_max']
                if not max_port and protocol != 'icmp':
                    max_port = 65535
                in_cmds, out_cmds = self._create_acl_on_eos(in_cmds, out_cmds,
                                                            protocol,
                                                            remote_ip,
                                                            min_port,
                                                            max_port,
                                                            sgr['direction'])
        return in_cmds, out_cmds

    def create_acl_rule(self, context, sgr):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        name = self._arista_acl_name(sgr['security_group_id'],
                                     sgr['direction'])
        cmds = []
        for c in self.aclCreateDict['create']:
            cmds.append(c.format(name))
        in_cmds, out_cmds = self._create_acl_rule(context, cmds, cmds, sgr)

        cmds = in_cmds
        if sgr['direction'] == 'egress':
            cmds = out_cmds

        cmds.append('exit')

        for server_id, s in six.iteritems(self._server_by_id):
            try:
                self._run_openstack_sg_cmds(cmds, s)
            except Exception as e:
                msg = (_('Failed to create ACL rule on EOS %(server)s '
                         ' due to %(exc)s') %
                       {'server': server_id, 'exc': e})
                LOG.debug(msg)

    def delete_acl_rule(self, sgr):
        """Deletes an ACL rule on Arista Switch.

        For a given Security Group (ACL), it removes a rule
        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        # Only deal with valid protocols - skip the rest
        if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
            return

        if sgr['protocol'] is None:
            protocols = SUPPORTED_SG_PROTOCOLS[:-1]
        else:
            protocols = [sgr['protocol']]

        # Build separate ACL for ingress and egress
        name = self._arista_acl_name(sgr['security_group_id'],
                                     sgr['direction'])
        remote_ip = sgr['remote_ip_prefix']
        if not remote_ip:
            remote_ip = 'any'
        min_port = sgr['port_range_min']
        if not min_port:
            min_port = 0

        for protocol in protocols:
            max_port = sgr['port_range_max']
            if not max_port and protocol != 'icmp':
                max_port = 65535
            for server_id, s in six.iteritems(self._server_by_id):
                try:
                    self._delete_acl_rule_from_eos(name,
                                                   sgr['protocol'],
                                                   remote_ip,
                                                   min_port,
                                                   max_port,
                                                   sgr['direction'],
                                                   s)
                except Exception as e:
                    msg = (_('Failed to delete ACL on EOS '
                             ' %(server)s (%(exc)s)') %
                           {'server': server_id, 'exc': e})
                    LOG.debug(msg)

    def _create_acl_shell(self, sg_id):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Build separate ACL for ingress and egress
        cmds = ([], [])
        for i, d in enumerate(DIRECTIONS):
            name = self._arista_acl_name(sg_id, d)
            for c in self.aclCreateDict['create']:
                cmds[i].append(c.format(name))
        return cmds

    @staticmethod
    def _find_element_in_list(element, list_element):
        try:
            index_element = list_element.index(element)
            return index_element
        except ValueError:
            return None

    @staticmethod
    def _consolidate_ips(
            dir,
            processed_cmds,
            consolidation_dict,
            min_prefixlen=32):

        def enlarge(network):
            network = IPNetwork(network)
            if network.prefixlen > min_prefixlen:
                network.prefixlen = min_prefixlen
            return network

        min_distance = None

        for prot, port_starts in six.iteritems(consolidation_dict):
            for port_min, port_ends in six.iteritems(port_starts):
                for port_max, ips in six.iteritems(port_ends):
                    if 'any' in ips:
                        ipset = IPSet(_ANY_IP_V4)
                    else:
                        ipset = IPSet(enlarge(ip) for ip in ips)

                    ipset.compact()

                    previous = None
                    for net in sorted(ipset.iter_cidrs()):
                        if previous:
                            distance = net.first - previous.last
                            if min_distance is None or distance < min_distance:
                                min_distance = distance
                        previous = net

                        if net.prefixlen == 0:
                            ip = 'any'
                        elif len(net) == 1:
                            ip = 'host ' + str(net.ip)
                        else:
                            ip = str(net)

                        is_icmp = prot == 'icmp'
                        pattern = _COMMAND_FORMAT_PATTERN[is_icmp][dir]
                        processed_cmds[dir].append(
                            pattern.format(
                                proto=prot,
                                host=ip,
                                port_min=port_min,
                                port_max=port_max,
                                flags='syn' if prot == 'tcp' else ''
                            ).strip()
                        )
        return min_distance

    def _consolidate_cmds(self, cmds):
        num_ingress = len(cmds['ingress'])
        num_egress = len(cmds['egress'])
        num_rules = num_ingress + num_egress - 4
        lossy = 0 < self.max_rules < num_rules
        min_prefixlen = 32 # Assumption -> no lossy compression needed

        while True:
            processed_cmds = {'ingress': [], 'egress': []}
            min_distance = None
            for dir in DIRECTIONS:
                consolidation_dict = defaultdict(
                    lambda: defaultdict(lambda: defaultdict(list)))
                for cmd in cmds[dir]:
                    icmp = cmd.startswith('permit icmp')
                    match = _COMMAND_PARSE_PATTERN[icmp][dir].match(cmd)
                    if match is not None:
                        # put in consolidation list
                        host = match.group('host')
                        proto = match.group('proto')
                        port_min = match.group('port_min')
                        port_max = match.group('port_max')

                        if icmp:
                            if port_min is None:
                                port_min = ''
                            if port_max is None:
                                port_max = ''

                        consolidation_dict[proto][port_min][port_max].\
                            append(host)
                    else:
                        processed_cmds[dir].append(cmd)

                min_distance_1 = self._consolidate_ips(
                    dir,
                    processed_cmds, consolidation_dict,
                    min_prefixlen
                )

                if min_distance is None or min_distance < min_distance_1:
                    min_distance = min_distance_1

            num_rules = len(processed_cmds['ingress']) \
                        + len(processed_cmds['egress']) - 4

            if self.max_rules <= 0 or num_rules <= self.max_rules \
                    or min_distance is None:
                break

            min_prefixlen -= min_distance.bit_length()
            cmds = processed_cmds

        if lossy:
            LOG.debug("Consolidated ACLs lossy from %d/%d to %d/%d!" %
                      (num_ingress,
                       num_egress,
                       len(processed_cmds['ingress']),
                       len(processed_cmds['egress'])))
        return processed_cmds

    @staticmethod
    def _sg_enable_dhcp(sg_rules):
        sg_rules = sorted(sg_rules)
        sg_rules.append({'protocol': 'dhcp',
                         'ethertype': 'IPv4',
                         'remote_ip_prefix': None,
                         'remote_group_id': None,
                         'port_range_min': 67,
                         'port_range_max': 68,
                         'direction': 'both'
                         })
        return sg_rules

    def _create_acl_diff(self, existing_acls, new_acls):
        """Accepts 2 cmd lists and creates a diff between them."""

        diff = []
        for new_acl in new_acls:
            # find all acls in existing set
            acls = list(filter(
                lambda x: x['text'] == new_acl or self._conv_acl(x) == new_acl,
                existing_acls))

            # new rule? add to doff
            if len(acls) == 0:
                diff.append(new_acl)
            else:
                # Mark them as already synced
                for acl in acls:
                    acl['synced'] = True
                    acl['duplicate'] = True
                acls[0]['duplicate'] = False

        diff += ['no {}'.format(acl['sequenceNumber'])
                 for acl in existing_acls
                 if 'synced' not in acl or acl.get('duplicate', False)]
        return diff

    def _conv_acl(self, acl):
        """Generates AristaACL rule text without port names if possible"""

        if 'ruleFilter' not in acl:
            return acl['text']

        ips = {'src': '', 'dst': ''}
        for dir, selector in zip(['src', 'dst'], ['source', 'destination']):

            if acl['ruleFilter'][selector]['mask'] == 0:
                ip = 'any'
            elif acl['ruleFilter'][selector]['mask'] == 1 << 32:
                ip = 'host ' + acl['ruleFilter'][selector]['ip']
            else:
                cidr_mask = int(
                    math.ceil(
                        math.log(acl['ruleFilter'][selector]['mask'], 2)))
                ip = acl['ruleFilter'][selector]['ip'] + '/' + str(cidr_mask)

            if acl['ruleFilter'][dir + 'Port']['oper'] == 'any':
                ips[dir] = ip
            elif acl['ruleFilter'][dir + 'Port']['oper'] == 'eq':
                ips[dir] = "{} eq {}".format(ip,
                                             ','.join([str(port) for port in
                                                       acl['ruleFilter'][
                                                           dir + 'Port'][
                                                           'ports']]))
            elif acl['ruleFilter'][dir + 'Port']['oper'] == 'range':
                ips[dir] = "{} range {}".format(ip, ' '.join(
                    [str(port) for port in
                     acl['ruleFilter'][dir + 'Port']['ports']]))

        prop = {
            'action': acl['action'],
            'protocol': self._protocol_table[
                acl['ruleFilter']['protocol']].lower(),
            'src': ips['src'],
            'dst': ips['dst'],
            'flags': 'syn' if acl['ruleFilter']['tcpFlags'] else ''
        }
        return "{action} {protocol} {src} {dst} {flags}".format(**prop).strip()

    def create_acl(self, context, sg,
                   security_group_ips=None, existing_acls=None, switches=None):
        """Creates an ACL on Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled or not sg:
            return

        security_group_id = sg['id']
        security_group_rules = self._sg_enable_dhcp(sg['security_group_rules'])

        cmds = {'ingress': list(self.aclCreateDict['tcp_established']),
                'egress': list(self.aclCreateDict['tcp_established'])}

        for sgr in security_group_rules:
            cmds['ingress'], cmds['egress'] = self._create_acl_rule(
                context,
                cmds['ingress'], cmds['egress'], sgr,
                security_group_ips=security_group_ips
            )

        num_rules = {'ingress': len(cmds['ingress']) - 2,
                     'egress': len(cmds['egress']) - 2}

        # let's consolidate
        cmds = self._consolidate_cmds(cmds)

        # Create per server diff and apply
        for server_id, s in six.iteritems(self._server_by_id):
            if switches is not None and server_id not in switches:
                continue
            server_diff = cmds.copy()
            for d, dir in enumerate(DIRECTIONS):
                tags = ['server.id:' + str(server_id),
                        'security.group:' + sg['id'],
                        'project.id:' + sg['tenant_id'], 'direction:' + dir
                        ]
                self._statsd.gauge('networking.arista.security.groups',
                                   num_rules[dir], tags=tags)

                acl_name = self._arista_acl_name(security_group_id, dir)
                if existing_acls is not None:
                    server_diff[dir] = self._create_acl_diff([
                        acl for acl in
                        existing_acls[s].get(acl_name, [])
                        if acl['text'] not in self.aclCreateDict['create']
                    ], cmds[dir])

                if len(server_diff[dir]) > 0:
                    server_diff[dir] = \
                        self._create_acl_shell(security_group_id)[d] + \
                        server_diff[dir] + ['exit']
            try:
                if len(server_diff['ingress']) + \
                        len(server_diff['egress']) > 0:
                    self._run_openstack_sg_cmds(
                        server_diff['ingress'] + server_diff['egress'], s)
            except Exception as error:
                msg = (_('Failed to create ACL on EOS %(server)s '
                         ' due to %(msg)s') %
                       {'server': server_id, 'msg': error.message})
                LOG.exception(msg)
                # raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_acl(self, sg):
        """Deletes an ACL from Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled:
            return

        if not sg:
            msg = _('Invalid or Empty Security Group Specified')
            raise arista_exc.AristaSecurityGroupError(msg=msg)

        for i, d in enumerate(DIRECTIONS):
            name = self._arista_acl_name(sg['id'], d)

            for server_id, s in six.iteritems(self._server_by_id):
                tags = ['server.id:' + str(server_id),
                        'security.group:' + sg['id'],
                        'project.id:' + sg['tenant_id'],
                        'direction:' + d
                        ]
                self._statsd.gauge('networking.arista.security.groups',
                                   0, tags=tags)
                try:
                    self._delete_acl_from_eos(name, s)
                except Exception as error:
                    msg = (_('Failed to delete ACL on EOS %s') % error)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)

    def apply_acl(self, sgs, switch_id=None, port_id=None, switch_info=None,
                  server=None):
        """Creates an ACL on Arista Switch.

        Applies ACLs to the baremetal ports only. The port/switch
        details is passed through the parameters.
        Deals with multiple configurations - such as multiple switches
        param sgs: List of Security Groups
        param switch_id: Switch ID of TOR where ACL needs to be applied
        param port_id: Port ID of port where ACL needs to be applied
        param switch_info: IP address of the TOR
        param server: Reference to the RPC Server for the switch
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled or not sgs:
            return

        if server is None:
            server = self._get_server(switch_info, switch_id)

        # We already have ACLs on the TORs.
        # Here we need to find out which ACL is applicable - i.e.
        # Ingress ACL, egress ACL or both
        cmds = []
        for dir in DIRECTIONS:
            name = self._arista_acl_name(sgs, dir)
            self._apply_acl_on_eos(port_id, name, dir, server, cmds)
        try:
            self._run_openstack_sg_cmds(cmds, server)
        except Exception:
            msg = (_('Failed to apply ACL on port %s') % port_id)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def remove_acl(self, sgs, switch_id=None, port_id=None, switch_info=None,
                   server=None):
        """Removes an ACL from Arista Switch.

        Removes ACLs from the baremetal ports only. The port/switch
        details is passed through the parameters.
        param sgs: List of Security Groups
        param switch_id: Switch ID of TOR where ACL needs to be removed
        param port_id: Port ID of port where ACL needs to be removed
        param switch_info: IP address of the TOR
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled or not sgs:
            return

        if server is None:
            server = self._get_server(switch_info, switch_id)

        # We already have ACLs on the TORs.
        # Here we need to find out which ACL is applicable - i.e.
        # Ingress ACL, egress ACL or both
        for dir in DIRECTIONS:
            name = self._arista_acl_name(sgs, dir)
            try:
                self._remove_acl_from_eos(port_id, name, dir, server)
            except Exception as e:
                msg = _('Failed to remove ACL on port %(port)s '
                        'due to %(msg)s') % {
                          'port': port_id,
                          'msg': e.message}
                LOG.exception(msg)
                # No need to raise exception for ACL removal
                # raise arista_exc.AristaSecurityGroupError(msg=msg)

    def _run_openstack_sg_cmds(self, commands, server):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param server: Server endpoint on the Arista switch to be configured
        """
        command_start = ['enable', 'configure']
        command_end = ['exit']
        full_command = command_start + commands + command_end

        LOG.debug('Executing command on Arista EOS: %s', full_command)

        try:
            # this returns array ofplug_port_into_network
            # return values for every command in
            # full_command list
            ret = server(full_command)
            LOG.debug('Results of execution on Arista EOS: %s', ret)
        except Exception as e:
            msg = (_('Error occurred while trying to execute '
                     'commands %(cmd)s: %(error)') %
                   {'cmd': full_command, 'error': e.message})
            LOG.exception(msg)
            raise arista_exc.AristaServicePluginRpcError(msg=msg)

        return ret

    @staticmethod
    def _security_group_name(name):
        if isinstance(name, six.string_types):
            return name

        if len(name) == 1:
            return name[0]
        else:
            s = sha1()
            for n in sorted(name):
                s.update(n)
            return s.hexdigest()

    @staticmethod
    def _arista_acl_name(name, direction):
        """Generate an Arista specific name for this ACL.

        Use a unique name so that OpenStack created ACLs
        can be distinguished from the user created ACLs
        on Arista HW.
        """
        in_out = 'OUT' if direction == 'egress' else 'IN'
        name = AristaSecGroupSwitchDriver._security_group_name(name)

        return '-'.join(['SG', in_out, name])

    @staticmethod
    def _switches_on_port(port):
        if not port:
            return

        profile = port['profile']
        if not isinstance(profile, dict):
            try:
                profile = json.loads(profile)
                port['profile'] = profile
            except ValueError:
                return

        link_info = profile.get('local_link_information') or []
        for l in link_info:
            if isinstance(l, dict):
                yield (l.get('switch_info'), EUI(l.get('switch_id'))),\
                      l.get('port_id')

    def perform_sync_of_sg(self, context):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot
        """
        # Do nothing if Security Groups are not enabled

        if not self.sg_enabled:
            return

        self._maintain_connections()

        arista_ports = db_lib.get_ports(context)
        arista_port_ids = set(arista_ports.iterkeys())
        sg_bindings = self._ndb.get_all_security_gp_to_port_bindings(
            context, filters={'port_id': arista_port_ids})
        neutron_sgs = self._ndb.get_security_groups(
            context, filters={'id': set(binding['security_group_id']
                                        for binding in sg_bindings)})

        all_sgs = collections.defaultdict(set)
        sgs_dict = collections.defaultdict(list)
        all_bm_ports = dict(db_lib.get_all_baremetal_ports(context))

        # Get the list of Security Groups of interest to us
        for s in sg_bindings:
            sgs_dict[s['port_id']].append(s['security_group_id'])

        for port_id, sgs in six.iteritems(sgs_dict):
            if sgs:
                port = all_bm_ports.get(port_id)
                for switch, port_id in self._switches_on_port(port):
                    all_sgs[tuple(sorted(sgs))].add(switch[-1])

        existing_acls = dict()
        pool = Pool()
        server_by_id = self._server_by_id

        for server, acls in itertools.izip(
                six.itervalues(server_by_id),
                pool.imap(
                    self._fetch_acls, six.itervalues(server_by_id))):
            existing = acls
            existing_acls[server] = existing

        # Create the ACLs on Arista Switches
        security_group_ips = {}
        known_acls = defaultdict(set)
        for sg_ids, switches in six.iteritems(all_sgs):
            if len(sg_ids) == 1:
                sg = neutron_sgs[sg_ids[0]]
            else:
                rules = []
                sg = {
                    'id': self._security_group_name(sg_ids),
                    'security_group_rules': rules,
                    'tenant_id': neutron_sgs[sg_ids[0]]['tenant_id']
                }

                for sg_id in sg_ids:
                    rules.extend(neutron_sgs[sg_id]['security_group_rules'])

            for direction in DIRECTIONS:
                for switch in switches:
                    server = server_by_id.get(switch)
                    if server:
                        known_acls[server].add(
                            self._arista_acl_name(sg['id'], direction)
                        )
            self.create_acl(context, sg,
                            security_group_ips=security_group_ips,
                            existing_acls=existing_acls,
                            switches=switches)

        # Get Baremetal port profiles, if any
        ports_by_switch = collections.defaultdict(dict)
        for port in six.itervalues(all_bm_ports):
            sgs = sgs_dict.get(port['port_id'], [])
            for switch, port_id in self._switches_on_port(port):
                ports_by_switch[switch][port_id] = sgs

        def sync_acl(switch, port_security_groups):
            server = self._get_server(*switch)
            if server is None:
                return
            self._sync_acls(server, port_security_groups, known_acls[server])

        for _sync_acl in pool.starmap(
                sync_acl, six.iteritems(ports_by_switch)):
            pass

    def _remove_unused_acls(self, server, unknown_acls):
        if not unknown_acls:
            return
        LOG.warning("Orphaned ACLs %s", unknown_acls)
        for name in unknown_acls:
            try:
                self._delete_acl_from_eos(name, server)
            except Exception as error:
                msg = (_('Failed to delete ACL on EOS: %s') % error)
                LOG.exception(msg)
                raise arista_exc.AristaSecurityGroupError(msg=msg)

    def _sync_acls(self, server, port_security_groups, known_acls):
        # Fetches the summary, which is the basis of all the current work
        port_to_acl = defaultdict(lambda: [None, None])
        summary = server(['show ip access-lists summary'])[0]
        acls_on_server = set()
        for acl_list in summary['aclList']:
            acl_name = acl_list['name']
            if not acl_name.startswith('SG-'):
                continue
            acls_on_server.add(acl_name)
            for i, dir in enumerate(INTERFACE_DIRECTIONS):
                for interface in acl_list[dir]:
                    if_name = interface['name']
                    port_to_acl[if_name][i] = acl_name

        # Get the port-channel memberships
        try:
            for k, pc in six.iteritems(self._get_interface_membership(
                    server, port_security_groups.iterkeys())):
                if pc not in port_security_groups:
                    port_security_groups[pc] = port_security_groups[k]
        except Exception:
            msg = (_('Failed to fetch interface memberships from EOS'))
            LOG.exception(msg)

        for port_id, sgs in six.iteritems(port_security_groups):
            acl_on_port = port_to_acl[port_id]
            if sgs:
                if all(acl_on_port[i]
                       == self._arista_acl_name(sgs, dir)
                       for i, dir in enumerate(DIRECTIONS)):
                    continue

                self.apply_acl(sgs, server=server, port_id=port_id)
            else:
                if acl_on_port != [None, None]:
                    try:
                        self._run_openstack_sg_cmds([
                            'interface ' + port_id,
                            'ip access-group default in',
                            'no ip access-group default in',
                            'ip access-group default out',
                            'no ip access-group default out',
                            'exit'
                        ], server)
                    except arista_exc.AristaServicePluginRpcError:
                        pass

        self._remove_unused_acls(server, acls_on_server - known_acls)

    @staticmethod
    def _fetch_acls(server):
        try:
            acls = server(['show ip access-lists'])[0]
            existing_acls = {
                acl['name']: acl['sequence']
                for acl in acls['aclList']
                if acl['name'].startswith('SG-')
            }

        except (HTTPException, TypeError):
            #  Request may return None -> None[0] -> TypeError
            LOG.warning("Failed to fetch the ip access-lists, "
                        "assuming empty list")
            existing_acls = {}
        return existing_acls
