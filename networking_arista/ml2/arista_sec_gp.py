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
import inspect
import itertools
import json
import math
import re
import requests
import six
import socket

from copy import copy
from eventlet.greenpool import GreenPool as Pool
from hashlib import sha1
from httplib import HTTPException
from six.moves.urllib.parse import urlparse

from netaddr import AddrFormatError
from netaddr import EUI
from netaddr import IPNetwork
from netaddr import IPSet
from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log as logging

from networking_arista._i18n import _
from networking_arista.common.constants import ANY_IP_V4
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import util

LOG = logging.getLogger(__name__)

# Note 'None,null' means default rule - i.e. deny everything
SUPPORTED_SG_PROTOCOLS = ['tcp', 'udp', 'icmp', 'dhcp', None]
SUPPORTED_SG_ETHERTYPES = ['IPv4']

DIRECTIONS = ['ingress', 'egress']
INTERFACE_DIRECTIONS = ['configuredEgressIntfs', 'configuredIngressIntfs']

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
            'in_rule': ['permit {0} {1} any range {2} {3}{4}'],
            'in_rule_norange': ['permit {0} {1} any{4}'],
            'in_rule_reverse': ['permit {0} any range {2} {3} {1}'],
            'in_rule_reverse_norange': ['permit {0} any {1}'],
            'out_rule': ['permit {0} any {1} range {2} {3}'],
            'out_rule_norange': ['permit {0} any {1}'],
            'out_rule_tcp': ['permit {0} any {1} range {2} {3}{4}'],
            'out_rule_tcp_norange': ['permit {0} any {1}{4}'],
            'out_rule_reverse': ['permit {0} {1} range {2} {3} any{4}'],
            'out_rule_reverse_norange': ['permit {0} {1} any{4}'],
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
                                'no permit {1} {2} any range {3}{4}',
                                'exit'],
            'del_in_acl_rule_norange': ['ip access-list {0}',
                                        'no permit {1} {2} any',
                                        'exit'],
            'del_out_acl_rule': ['ip access-list {0}',
                                 'no permit {1} any {2} range {3}{4}',
                                 'exit'],
            'del_out_acl_rule_norange': ['ip access-list {0}',
                                         'no permit {1} any {2}',
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
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?P<src_range> range \w+ \w+)? "
            r"any"
            r"(?: range (?P<port_min>\w+) (?P<port_max>\w+))?(?P<flags> syn)?$"
        ),
        'egress': re.compile(
            r"^permit (?P<proto>udp|tcp) "
            r"any"
            r"(?P<src_range> range \w+ \w+)? "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?P<dst_range> range (?P<port_min>\w+) (?P<port_max>\w+))?"
            r"(?P<flags> syn)?$"
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
    },
    'dhcp': {
        'ingress': re.compile(
            r"^permit (?P<proto>udp) "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?P<src_range> eq \w+) "
            r"any"
            r" eq (?=(?P<port_min>\w+)$)(?P<port_max>\w+)"
            r"(?P<flags> \w+)?$"  # will never match any flags
        ),
        'egress': re.compile(
            r"^permit (?P<proto>udp) "
            r"any"
            r"(?P<src_range> eq \w+) "
            r"(?:host )?"
            r"(?P<host>\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?|any)"
            r"(?P<dst_range> eq (?=(?P<port_min>\w+)$)(?P<port_max>\w+))$"
            r"(?P<flags> \w+)?$"  # will never match any flags
        ),
    }
}

_COMMAND_FORMAT_PATTERN = {
    False: {
        'ingress':
            'permit {proto} {host}{src_range} '
            'any range {port_min} {port_max}{flags}',
        'ingress_norange':
            'permit {proto} {host}{src_range} any{flags}',
        'egress':
            'permit {proto} any{src_range} {host}{dst_range}{flags}'
    },
    True: {
        'ingress':
            'permit {proto} {host} any {port_min} {port_max}',
        'egress':
            'permit {proto} any {host} {port_min} {port_max}'
    }
}

_IP_ACL_SUBNET_RE = re.compile(r"(?:^| )"
                               r"(?P<net>\d+\.\d+\.\d+\.\d+/\d+)"
                               r"(?= |$)")


class HashableDict(dict):
    def __key(self):
        return tuple((k, self[k]) for k in sorted(self))

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()


class AristaSwitchRPCMixin(object):
    _SERVER_BY_ID = dict()
    _SERVER_BY_IP = dict()
    _INTERFACE_MEMBERSHIP = collections.defaultdict(dict)
    _PORTCHANNEL_MEMBERSHIP = collections.defaultdict(dict)

    def __init__(self, *args, **kwargs):
        super(AristaSwitchRPCMixin, self).__init__()
        self._statsd = util.STATS
        self._conn_timeout = cfg.CONF.ml2_arista.conn_timeout
        self._verify = cfg.CONF.ml2_arista.verify_ssl
        self._session = kwargs.get('session') or util.make_http_session()
        self._sg_disabled_device_ids = []

        for dev_id in cfg.CONF.ml2_arista.\
                disable_sec_group_support_on_device_ids:
            self._sg_disabled_device_ids.append(EUI(dev_id))

        if self._requests_send_metrics_hook not in \
                self._session.hooks['response']:
            self._session.hooks['response'].append(
                    self._requests_send_metrics_hook)

    def _requests_send_metrics_hook(self, r, *args, **kwargs):
        """Send request duration to statsd server

        This function should be used as a response hook for the requests
        library.
        """
        # find out callee of _send_eapi_req (but not server())
        callee_name = "<undefined>"
        try:
            eapi_req_found = False
            for frame in inspect.stack():
                func_name = frame[3]
                if not eapi_req_found and func_name == '_send_eapi_req':
                    eapi_req_found = True
                elif eapi_req_found and func_name not in ('server', 'wrapped'):
                    callee_name = func_name
                    break
        except Exception:
            pass

        # parse url to get hostname later on
        parsed_url = urlparse(r.url)

        tags = [
            'switch.ip:{}'.format(parsed_url.hostname),
            'python_callee:{}'.format(callee_name),
            'http_status_code:{}'.format(r.status_code),
        ]
        self._statsd.histogram(
            'networking.arista.apicall_http_duration_seconds',
            r.elapsed.total_seconds(), tags=tags)

        # look for response timings in API json response
        try:
            responses = r.json()
            exec_duration = 0
            for response in responses['result']:
                exec_duration += response['_meta']['execDuration']

            self._statsd.histogram(
                'networking.arista.apicall_exec_duration_seconds',
                exec_duration, tags=tags)
        except Exception:
            pass

    def _refresh_interface_membership(self, server):
        """Update portchannel interface membership from switch"""
        membership = {}
        pc_members = collections.defaultdict(set)

        ret = server(["show port-channel summary"])
        if ret and ret[0]:
            switch_pcs = ret[0]['portChannels']
            for pc in switch_pcs:
                for iface in switch_pcs[pc]['ports']:
                    membership[iface] = pc
                    pc_members[pc].add(iface)

        if membership:
            self._INTERFACE_MEMBERSHIP[server] = membership
            self._PORTCHANNEL_MEMBERSHIP[server] = pc_members

    def _get_interface_membership(self, server, ports):
        """Get portchannel membership information for a list of ports"""
        ifm = self._INTERFACE_MEMBERSHIP[server]

        if any(port not in ifm for port in ports):
            self._refresh_interface_membership(server)
            ifm = self._INTERFACE_MEMBERSHIP[server]  # regrab updated mapping

        membership = {}
        for port in ports:
            if port in ifm:
                membership[port] = ifm[port]

        return membership

    def _get_portchannel_membership(self, server, portchannel):
        """Get portchannel membership information for a list of ports"""
        if portchannel not in self._PORTCHANNEL_MEMBERSHIP[server]:
            self._refresh_interface_membership(server)

        return self._PORTCHANNEL_MEMBERSHIP[server][portchannel]

    def _get_mlag_neighbor_server(self, server):
        """Get the server() for an mlag neighbor of a server()"""
        # find mlag neighbor
        mlag_detail = server(["show mlag detail"])
        if not (mlag_detail and mlag_detail[0]):
            LOG.warning("Could not fetch mlag details on switch %s",
                        self._get_info_by_server(server))
            return None
        neigh = EUI(mlag_detail[0]['detail']['peerMacAddress'])
        neigh_server = self._get_server(self, switch_id=neigh)
        if not neigh_server:
            LOG.warning("Could not find mlag neighbor %s in switch list "
                        "on server %s",
                        neigh, self._get_info_by_server(server))
            return None
        return neigh_server

    def _get_mlag_pc_members_from_iface(self, server, port_id):
        """Find all ifaces for a pc on an mlag switchpair

        Starting with an interface we find the pc and mlag peer, then
        grab all ifaces belonging to this pc on both sides of the mlag
        """
        result = set()
        result.add((server, port_id))

        pcs = self._get_interface_membership(server, [port_id])
        if not pcs:
            return result

        pc = pcs[port_id]
        servers = [server]
        mlag_neighbor = self._get_mlag_neighbor_server(server)
        if mlag_neighbor:
            servers.append(mlag_neighbor)

        for _server in servers:
            result.add((_server, pc))
            ifaces = self._get_portchannel_membership(_server, pc)
            for iface in ifaces:
                if not iface.startswith("Peer"):
                    result.add((_server, iface))

        return result

    def _send_eapi_req(self, switch_ip, switch_user, switch_pass, cmds):
        # This method handles all EAPI requests (using the requests library)
        # and returns either None or response.json()['result'] from the EAPI
        # request.
        #
        # Exceptions related to failures in connecting/ timeouts are caught
        # here and logged. Other unexpected exceptions are logged and raised

        if switch_pass == "''":
            switch_pass = ''
        eapi_server_url = ('https://%s:%s@%s/command-api' %
                           (switch_user, switch_pass, switch_ip))
        redacted_eapi_server_url = ('https://%s:%s@%s/command-api' %
                                    (switch_user, '<redacted>', switch_ip))

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
            LOG.debug("Sending %s to switch %s", cmds, switch_ip)
            response = self._session.post(
                eapi_server_url,
                verify=self._verify,
                timeout=self._conn_timeout,
                json=data)
            try:
                return response.json()['result']
            except KeyError as e:
                msg = ("Unexpected EAPI error - KeyError {} - result was {}"
                       "".format(e, response.json()))
                LOG.info(msg)
                raise arista_exc.AristaRpcError(msg=msg)
        except requests.exceptions.ConnectTimeout:
            msg = (_('Timed out while trying to connect to %(url)s') %
                   {'url': redacted_eapi_server_url})
            LOG.warning(msg)
            return None
        except requests.exceptions.ReadTimeout:
            msg = (_('Timed out while reading from %(url)s') %
                   {'url': redacted_eapi_server_url})
            LOG.warning(msg)
            return None
        except requests.exceptions.ConnectionError as e:
            msg = (_('Error while trying to connect to %(url)s'
                     'due to %(reason)s') %
                   {'url': redacted_eapi_server_url, 'reason': e})
            LOG.warning(msg)
            return None
        except requests.exceptions.InvalidURL:
            msg = (_('Ignore attempt to connect to invalid URL %(url)s') %
                   {'url': redacted_eapi_server_url})
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
        try:
            def server(cmds):
                return self._send_eapi_req(switch_ip, switch_user, switch_pass,
                                           cmds)

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

    def _get_id_by_server(self, server):
        for _idx, _srv in self._SERVER_BY_ID.items():
            if _srv == server:
                return _idx

    def _get_ip_by_server(self, server):
        for _idx, _srv in self._SERVER_BY_IP.items():
            if _srv == server:
                return _idx

    def _get_info_by_server(self, server):
        return self._get_id_by_server(server), self._get_ip_by_server(server)

    def _get_server_by_id(self, switch_id):
        return switch_id and self._SERVER_BY_ID.get(EUI(switch_id))

    def _get_server_by_ip(self, switch_ip):
        return switch_ip and self._SERVER_BY_IP.get(switch_ip)

    def _get_server(self, switch_info=None, switch_id=None):
        server = (self._get_server_by_id(switch_id) or
                  self._get_server_by_ip(switch_info))

        if server:
            return server

        self._maintain_connections()

        return (self._get_server_by_id(switch_id) or
                self._get_server_by_ip(switch_info))


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
            rule_ext = ''
            if from_port <= 1 and to_port == 65535:
                rule_ext = '_norange'
            flags = ''
            if direction == 'egress':
                if protocol == 'tcp':
                    flags = ' syn'
                    out_rule = self.aclCreateDict['out_rule_tcp' + rule_ext]
                    in_rule = []
                else:
                    flags = ' range 32768 65535'
                    out_rule = self.aclCreateDict['out_rule' + rule_ext]
                    in_rule = self.aclCreateDict['out_rule_reverse' + rule_ext]
            else:
                in_rule = self.aclCreateDict['in_rule' + rule_ext]
                if protocol == 'tcp':
                    flags = ' syn'
                    out_rule = []
                else:
                    out_rule = self.aclCreateDict['in_rule_reverse' + rule_ext]

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
            rule_ext = ''
            if from_port <= 1 and to_port == 65535:
                rule_ext = '_norange'

            acl_dict = self.aclCreateDict['del_in_acl_rule' + rule_ext]
            if direction == 'egress':
                acl_dict = self.aclCreateDict['del_out_acl_rule' + rule_ext]

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
                fetched = db_lib.select_ips_for_remote_group(
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
        fmt = util.PartialFormatter()

        def enlarge(network):
            network = IPNetwork(network)
            if network.prefixlen > min_prefixlen:
                try:
                    network.prefixlen = min_prefixlen
                except AddrFormatError:
                    pass
            return network

        min_distance = None

        for keys, ips in six.iteritems(consolidation_dict):
            if 'any' in ips:
                ipset = IPSet(ANY_IP_V4)
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

                is_icmp = keys['proto'] == 'icmp'
                rule_ext = ''
                if not is_icmp and dir == 'ingress' and \
                        keys.get('port_min') is None and \
                        keys.get('port_max') is None:
                    rule_ext = '_norange'

                pattern = _COMMAND_FORMAT_PATTERN[is_icmp][dir + rule_ext]
                cmd = fmt.format(pattern, host=ip, **keys).strip()
                processed_cmds[dir].append(cmd)
        return min_distance

    def _consolidate_portranges(self, cmds):
        """Remove rules for which we already have a portless permit

        If we already permit all tcp traffic for 10.0.0.0/8 syn, then
        we don't need any other rules specifying port ranges
        """
        def make_key(parsed_rule, ignore_host=False, ignore_src_range=False):
            host = 'any' if ignore_host else parsed_rule.group('host')
            src_range = None if ignore_src_range else \
                parsed_rule.group('src_range')

            return (parsed_rule.group('proto'),
                    host,
                    src_range,
                    parsed_rule.group('flags'))

        processed_cmds = {'ingress': [], 'egress': []}
        for _dir in DIRECTIONS:
            parsed_rules = []
            covering_rules = set()
            for cmd in cmds[_dir]:
                parsed_rule = None
                if not cmd.startswith("permit icmp"):
                    # parse rule for tcp/udp (False) or dhcp, if eq is present
                    rule_type = 'dhcp' if ' eq ' in cmd else False
                    parsed_rule = \
                        _COMMAND_PARSE_PATTERN[rule_type][_dir].match(cmd)
                    if parsed_rule:
                        # check if this rule covers all ports
                        covers_all_ports = False
                        if parsed_rule.group('port_min') in \
                                ('0', '1', 'tcpmux', None) and \
                                parsed_rule.group('port_max') \
                                in ('65535', None):
                            key = make_key(parsed_rule)
                            covering_rules.add(key)
                            covers_all_ports = True
                        parsed_rules.append((
                            cmd, parsed_rule, covers_all_ports))
                if not parsed_rule:
                    parsed_rules.append((cmd, None, None))

            for rule, parsed_rule, covers_all_ports in parsed_rules:
                if parsed_rule:
                    # find out if a rule exists that is not this rule but
                    # covers us by having no port range, (no port range and no
                    # src port range) or (no port range, no src port range and
                    # no host) specified - if so, drop the rule
                    rule_key = make_key(parsed_rule)
                    rule_nosrc = make_key(parsed_rule, ignore_src_range=True)
                    rule_proto = make_key(parsed_rule, ignore_src_range=True,
                                          ignore_host=True)
                    if not covers_all_ports and rule_key in covering_rules or \
                        (not covers_all_ports or rule_key != rule_nosrc) and \
                        rule_nosrc in covering_rules or \
                        (not covers_all_ports or rule_key != rule_proto) and \
                            rule_proto in covering_rules:
                        # ignore rule
                        pass
                    else:
                        processed_cmds[_dir].append(rule)
                else:
                    processed_cmds[_dir].append(rule)

        LOG.debug("Consolidated ACLs port merge result from %d/%d to %d/%d",
                  len(cmds['ingress']), len(cmds['egress']),
                  len(processed_cmds['ingress']),
                  len(processed_cmds['egress']))
        return processed_cmds

    def _consolidate_cmds(self, cmds):
        num_ingress = len(cmds['ingress'])
        num_egress = len(cmds['egress'])
        num_rules = num_ingress + num_egress - 4
        lossy = 0 < self.max_rules < num_rules
        min_prefixlen = 32  # Assumption -> no lossy compression needed

        # consolidate based on src/dst ip, merge ranges
        while min_prefixlen >= 0:
            processed_cmds = {'ingress': [], 'egress': []}
            min_distance = None
            for dir in DIRECTIONS:
                consolidation_dict = collections.defaultdict(list)

                for cmd in cmds[dir]:
                    icmp = cmd.startswith('permit icmp')
                    match = _COMMAND_PARSE_PATTERN[icmp][dir].match(cmd)
                    if match is not None:
                        items = match.groupdict()
                        host = items.pop('host')
                        keyed = HashableDict(items)
                        consolidation_dict[keyed].append(host)
                    else:
                        processed_cmds[dir].append(cmd)

                min_distance_1 = self._consolidate_ips(
                    dir,
                    processed_cmds, consolidation_dict,
                    min_prefixlen
                )

                if min_distance is None or min_distance < min_distance_1:
                    min_distance = min_distance_1

            num_rules = len(
                processed_cmds['ingress']) + len(processed_cmds['egress']) - 4

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

        # consolidate based on src/dst port
        processed_cmds = self._consolidate_portranges(processed_cmds)

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

    @staticmethod
    def _clear_hostbits_from_acl(rule):
        """Find ip subnets in ACLs and clear hostbits, if present"""
        for net_str in _IP_ACL_SUBNET_RE.findall(rule):
            net = IPNetwork(net_str)
            # check if hostbits are set
            if net.ip != net.network:
                rule = re.sub(
                            '(^| ){}( |$)'.format(re.escape(net_str)),
                            r'\g<1>{}\g<2>'.format(str(net.cidr)),
                            rule)

        return rule

    def _create_acl_diff(self, existing_acls, new_acls):
        """Accepts 2 cmd lists and creates a diff between them."""

        diff = []
        for new_acl in new_acls:
            # find all acls in existing set
            new_acl_without_hostbits = self._clear_hostbits_from_acl(new_acl)
            acls = list(filter(
                lambda x: (x['text'] == new_acl or
                           x['text'] == new_acl_without_hostbits or
                           self._conv_acl(x) == new_acl),
                existing_acls))

            # new rule? add to doff
            if not acls:
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
            elif acl['ruleFilter'][selector]['mask'] == ((1 << 32) - 1):
                ip = 'host ' + acl['ruleFilter'][selector]['ip']
            else:
                # convert netmask integer to CIDR notation
                # we do this by inverting the mask, then "count" the 1s via log
                mask_int = acl['ruleFilter'][selector]['mask']
                cidr_mask = 32 - int(math.log((0xFFFFFFFF ^ mask_int) + 1, 2))
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

        flags = ''
        if acl['ruleFilter']['tcpFlags']:
            flags = ' syn'
        elif acl['ruleFilter']['protocol'] == 1 and (
                acl['ruleFilter']['icmp']['code'] not in (0, 65535) or
                acl['ruleFilter']['icmp']['type'] not in (0, 65535)):
            flags = ' {code} {type}'.format(**acl['ruleFilter']['icmp'])

        prop = {
            'action': acl['action'],
            'protocol': self._protocol_table[
                acl['ruleFilter']['protocol']].lower(),
            'src': ips['src'],
            'dst': ips['dst'],
            'flags': flags,
        }
        return "{action} {protocol} {src} {dst}{flags}".format(**prop)

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
        security_group_rules = util.optimize_security_group_rules(
            security_group_rules)

        cmds = {'ingress': list(self.aclCreateDict['tcp_established']),
                'egress': list(self.aclCreateDict['tcp_established'])}

        for sgr in security_group_rules:
            cmds['ingress'], cmds['egress'] = self._create_acl_rule(
                context,
                cmds['ingress'], cmds['egress'], sgr,
                security_group_ips=security_group_ips
            )

        num_rules_initial = {
            'ingress': len(cmds['ingress']) - 2,
            'egress': len(cmds['egress']) - 2
        }

        # let's consolidate
        cmds = self._consolidate_cmds(cmds)

        num_rules_actual = {
            'ingress': len(cmds['ingress']) - 2,
            'egress': len(cmds['egress']) - 2
        }

        if 'ids' in sg:
            sg_ids = '-'.join(sg['ids'])
        else:
            sg_ids = sg['id']
        # Create per server diff and apply
        for server_id, s in six.iteritems(self._server_by_id):
            if switches is not None and server_id not in switches:
                continue
            server_diff = cmds.copy()
            for d, dir in enumerate(DIRECTIONS):
                tags = ['server.id:' + str(server_id),
                        'security.group:' + sg_ids,
                        'project.id:' + sg['tenant_id'],
                        'direction:' + dir,
                        'phase:initial'
                        ]
                self._statsd.gauge('networking.arista.security.groups',
                                   num_rules_initial[dir], tags=tags)

                tags[-1] = 'phase:actual'
                self._statsd.gauge('networking.arista.security.groups',
                                   num_rules_actual[dir], tags=tags)

                acl_name = self._arista_acl_name(security_group_id, dir)
                if existing_acls is not None:
                    acls = existing_acls[s].get(acl_name, [])
                    server_diff[dir] = self._create_acl_diff([
                        acl for acl in
                        acls
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
            # this returns array of plug_port_into_network
            # return values for every command in
            # full_command list
            ret = server(full_command)
            LOG.debug('Results of execution on Arista EOS: %s', ret)
        except Exception as e:
            msg = (_('Error occurred while trying to execute '
                     'commands %(cmd)s: %(error)s') %
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
        known_acls = collections.defaultdict(set)
        for sg_ids, switches in six.iteritems(all_sgs):
            if len(sg_ids) == 1:
                sg = neutron_sgs[sg_ids[0]]
            else:
                rules = []
                sg = {
                    'id': self._security_group_name(sg_ids),
                    'ids': sg_ids,
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
            self._sync_acls(server, port_security_groups, known_acls[server],
                            switch_id=switch[1])

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

    def _sync_acls(self, server, port_security_groups, known_acls, switch_id):
        # Fetches the summary, which is the basis of all the current work
        port_to_acl = collections.defaultdict(lambda: [None, None])
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
                    server, port_security_groups.keys())):
                if pc not in port_security_groups:
                    port_security_groups[pc] = port_security_groups[k]
        except Exception:
            msg = (_('Failed to fetch interface memberships from EOS'))
            LOG.exception(msg)

        for port_id, sgs in six.iteritems(port_security_groups):
            acl_on_port = port_to_acl[port_id]
            if sgs and switch_id not in self._sg_disabled_device_ids:
                if all(acl_on_port[i] == self._arista_acl_name(sgs, dir)
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
