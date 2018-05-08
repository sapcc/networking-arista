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
import json
import math
import os
import re
import socket
import ssl
from collections import defaultdict
from hashlib import sha1
from httplib import HTTPException

import jsonrpclib
import six
from netaddr import EUI, IPSet, IPNetwork
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils.importutils import try_import

from networking_arista._i18n import _, _LI
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc

dogstatsd = try_import('datadog.dogstatsd')

if not dogstatsd or os.getenv('STATSD_MOCK', False):
    from mock import Mock
    STATS = Mock()
else:
    STATS = dogstatsd.DogStatsd(host=os.getenv('STATSD_HOST', 'localhost'),
                                port=int(os.getenv('STATSD_PORT', 9125)),
                                namespace=os.getenv('STATSD_PREFIX', 'openstack')
                                )


LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')

# Note 'None,null' means default rule - i.e. deny everything
SUPPORTED_SG_PROTOCOLS = ['tcp', 'udp', 'icmp', 'dhcp', None]
SUPPORTED_SG_ETHERTYPES = ['IPv4']

DIRECTIONS = ['ingress', 'egress']
INTERFACE_DIRECTIONS = ['configuredEgressIntfs', 'configuredIngressIntfs']

acl_cmd = {  # For a rule 0: protocol, 1: cidr, 2: from_port, 3: to_port, 4: flags
    'acl': {'create': ['ip access-list {0}',
                       'permit tcp any any established'],
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


class AristaSecGroupSwitchDriver(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """

    def __init__(self, neutron_db):
        self._ndb = neutron_db
        self._server_by_id = dict()
        self._server_by_ip = dict()
        self.sg_enabled = cfg.CONF.ml2_arista.get('sec_group_support')
        self._validate_config()
        self._maintain_connections()
        self._statsd = STATS
        self.max_rules = cfg.CONF.ml2_arista.get('lossy_consolidation_limit')
        self._protocol_table = {
            num: name[8:] for name, num in vars(socket).items()
            if name.startswith("IPPROTO")
        }

        self.aclCreateDict = acl_cmd['acl']
        self.aclApplyDict = acl_cmd['apply']

    def _maintain_connections(self):
        for s in cfg.CONF.ml2_arista.switch_info:
            switch_ip, switch_user, switch_pass = s.split(":")
            if switch_ip in self._server_by_ip:
                continue

            if switch_pass == "''":
                switch_pass = ''
            eapi_server_url = ('https://%s:%s@%s/command-api' %
                               (switch_user, switch_pass, switch_ip))
            transport = jsonrpclib.jsonrpc.SafeTransport()
            # TODO: Make that a configuration value
            if hasattr(ssl, '_create_unverified_context'):
                transport.context = ssl._create_unverified_context()
            server = jsonrpclib.Server(eapi_server_url, transport=transport)
            try:
                ret = server.runCmds(version=1, cmds=["show lldp local-info management 1"])
                system_id = EUI(ret[0]['chassisId'])
                self._server_by_id[system_id] = server
                self._server_by_ip[switch_ip] = server
            except (socket.error, HTTPException) as e:
                LOG.warn("Could not connect to server %s due to %s", switch_ip, e)

    def _get_server(self, switch_info, switch_id):
        return self._server_by_ip.get(switch_info) \
               or self._server_by_id.get(EUI(switch_id))

    def _validate_config(self):
        if not self.sg_enabled:
            return
        if len(cfg.CONF.ml2_arista.get('switch_info')) < 1:
            msg = _('Required option - when "sec_group_support" is enabled, '
                    'at least one switch must be specified ')
            LOG.exception(msg)
            raise arista_exc.AristaConfigError(msg=msg)

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
                in_cmds.append(c.format(protocol, cidr, from_port, to_port, flags).strip())

            for c in out_rule:
                out_cmds.append(c.format(protocol, cidr, from_port, to_port, flags).strip())

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
            if ((from_port and to_port) or
                    (not from_port and not to_port)):
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

    def _apply_acl_on_eos(self, port_id, name, direction, server, accumulator=None):
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

    def _create_acl_rule(self, in_cmds, out_cmds, sgr, security_group_ips=None):
        """Creates an ACL on Arista Switch.

        For a given Security Group (ACL), it adds additional rule
        Deals with multiple configurations - such as multiple switches
        """
        # Only deal with valid protocols - skip the rest
        if not sgr or sgr['protocol'] not in SUPPORTED_SG_PROTOCOLS:
            return in_cmds, out_cmds

        if sgr['ethertype'] is not None and sgr['ethertype'] not in SUPPORTED_SG_ETHERTYPES:
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
                fetched = self._ndb._select_ips_for_remote_group(self._ndb.admin_ctx, [remote_group_id])
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

    def create_acl_rule(self, sgr):
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
        in_cmds, out_cmds = self._create_acl_rule(cmds, cmds, sgr)

        cmds = in_cmds
        if sgr['direction'] == 'egress':
            cmds = out_cmds

        cmds.append('exit')

        for server_id, s in six.iteritems(self._server_by_id):
            try:
                self._run_openstack_sg_cmds(cmds, s)
            except Exception as e:
                msg = (_('Failed to create ACL rule on EOS %s due to %s') %
                       (server_id, e))
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
                    msg = (_('Failed to delete ACL on EOS %s (%s)') %
                            (server_id, e))
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
    def _consolidate_ips(consolidation_dict, lossy=False):
        for prot, port_starts in six.iteritems(consolidation_dict):
            for port_start, port_ends in six.iteritems(port_starts):
                for port_end, ips in six.iteritems(port_ends):
                    if 'any' in ips:
                        ipset = IPSet(IPNetwork('0.0.0.0/0'))
                    else:
                        ipset = IPSet(ips)

                    def enlarge(network):
                        if network.prefixlen > 24:
                            network.prefixlen = 24
                        return network

                    if lossy:
                        ipset = IPSet([enlarge(network) for network in ipset.iter_cidrs()])

                    for net in ipset.iter_cidrs():
                        yield (prot, str(net), port_start, port_end,
                               'syn' if prot == 'tcp' else '')

    def _consolidate_cmds(self, cmds, num_rules):
        r = {
            # This compacts typical setups by using other security groups as rule
            # e.g. Match 'permit tcp host 10.180.1.2 any range 10000 10000 syn'
            'ingress': re.compile(r"^permit (udp|tcp) (?:host )?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,3})?|any) any range (\w+) (\w+)(?: syn)?"),
            #'egress': re.compile(r"^permit (udp|tcp) any (?:host )?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,3})?|any) range (\w+) (\w+)(?: syn)?")
            'egress': re.compile(r"^permit (udp|tcp) any range (\w+) (\w+) (?:host )?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,3})?|any)(?: syn)?")
        }

        processed_cmds = {'ingress': [], 'egress': []}
        for dir in DIRECTIONS:
            consolidation_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
            for cmd in cmds[dir]:
                match = r[dir].match(cmd)
                if match is not None:
                    # put in consolidation list
                    if dir == 'ingress':
                        (prot, host, port_start, port_end) = match.groups()
                    else:
                        (prot, port_start, port_end, host) = match.groups()
                    consolidation_dict[prot][port_start][port_end].append(host)
                else:
                    processed_cmds[dir].append(cmd)

            for network in self._consolidate_ips(consolidation_dict, lossy=(0 < self.max_rules < num_rules)):
                if dir == 'ingress':
                    processed_cmds[dir].append(("permit %s %s any range %s %s %s" % network).strip())
                else:
                    processed_cmds[dir].append(("permit %s any %s range %s %s %s" % network).strip())

        LOG.debug("Consolidated ACLs from %d/%d to %d/%d!" %
                  (len(cmds['ingress']),
                   len(cmds['egress']),
                   len(processed_cmds['ingress']),
                   len(processed_cmds['egress'])))
        return processed_cmds

    @staticmethod
    def _sg_enable_dhcp(sg_rules):
        sg_rules.append({'protocol': 'dhcp',
                         'ethertype': 'IPv4',
                         'remote_ip_prefix': None,
                         'remote_group_id': None,
                         'port_range_min': 67,
                         'port_range_max': 68,
                         'direction': 'both'
                         })

    def _create_acl_diff(self, existing_acls, new_acls):
        """Accepts 2 cmd lists and creates a diff between them."""

        diff = list(new_acls)
        for existing_acl in existing_acls:
            found = False
            for new_acl in new_acls:
                # Rules exists, don't reapply
                if new_acl in [existing_acl['text'], self._conv_acl(existing_acl)]:
                    diff.remove(new_acl)
                    found = True

            if not found:
                # delete rule
                diff.append(str('no ' + existing_acl['text']))
        return diff

    def _conv_acl(self, acl):
        """Generates AristaACL rule text without port names if possible"""

        if 'ruleFilter' not in acl:
            return acl['text']

        ips = {'src': '', 'dst': ''}
        for dir in ['src', 'dst']:
            if acl['ruleFilter']['source' if dir == 'src' else 'destination']['mask'] == 0:
                ip = 'any'
            elif acl['ruleFilter']['source' if dir == 'src' else 'destination']['mask'] == 1 << 32:
                ip = 'host ' + acl['ruleFilter']['source' if dir == 'src' else 'destination']['ip']
            else:
                cidr_mask = int(round(math.log(4L, 2)))
                ip = acl['ruleFilter']['source' if dir == 'src' else 'destination']['ip'] + '/' + str(cidr_mask)

            if acl['ruleFilter'][dir + 'Port']['oper'] == 'any':
                ips[dir] = ip
            elif acl['ruleFilter'][dir + 'Port']['oper'] == 'eq':
                ips[dir] = "{} eq {}".format(ip,
                                             ','.join([str(port) for port in acl['ruleFilter'][dir + 'Port']['ports']]))
            elif acl['ruleFilter'][dir + 'Port']['oper'] == 'range':
                ips[dir] = "{} range {}".format(ip, ' '.join(
                    [str(port) for port in acl['ruleFilter'][dir + 'Port']['ports']]))

        prop = {
            'action': acl['action'],
            'protocol': self._protocol_table[acl['ruleFilter']['protocol']].lower(),
            'src': ips['src'],
            'dst': ips['dst'],
            'flags': 'syn' if acl['ruleFilter']['tcpFlags'] else ''
        }
        return "{action} {protocol} {src} {dst} {flags}".format(**prop).strip()

    def create_acl(self, sg, security_group_ips=None, existing_acls=None):
        """Creates an ACL on Arista Switch.

        Deals with multiple configurations - such as multiple switches
        """
        # Do nothing if Security Groups are not enabled
        if not self.sg_enabled or not sg:
            return

        security_group_id = sg['id']
        security_group_rules = list(sg['security_group_rules'])

        self._sg_enable_dhcp(security_group_rules)

        cmds = {'ingress': [], 'egress': []}
        for sgr in security_group_rules:
            cmds['ingress'], cmds['egress'] = self._create_acl_rule(
                cmds['ingress'], cmds['egress'], sgr,
                security_group_ips=security_group_ips
            )

        num_rules = {'ingress': len(cmds['ingress']) - 2, 'egress': len(cmds['egress']) - 2}

        # let's consolidate
        cmds = self._consolidate_cmds(cmds, num_rules['ingress'] + num_rules['egress'])

        # Create per server diff and apply
        for server_id, s in six.iteritems(self._server_by_id):
            server_diff = cmds.copy()
            for d, dir in enumerate(DIRECTIONS):
                tags = ['server.id:' + str(server_id), 'security.group:' + sg['id'],
                        'project.id:' + sg['tenant_id'], 'direction:' + dir
                        ]
                self._statsd.gauge('networking.arista.security.groups', num_rules[dir], tags=tags)

                acl_name = self._arista_acl_name(security_group_id, dir)
                if existing_acls is not None:
                    server_diff[dir] = self._create_acl_diff([
                        acl for acl in existing_acls[server_id].get(acl_name, [])
                        if acl['text'] not in self.aclCreateDict['create']
                    ], cmds[dir])

                if len(server_diff[dir]) > 0:
                    server_diff[dir] = self._create_acl_shell(security_group_id)[d] + server_diff[dir] + ['exit']
            try:
                if len(server_diff['ingress']) + len(server_diff['egress']) > 0:
                    self._run_openstack_sg_cmds(server_diff['ingress'] + server_diff['egress'], s)
            except Exception as error:
                msg = (_('Failed to create ACL on EOS %s: %s') % (server_id, error.message))
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
                tags = ['server.id:' + str(server_id), 'security.group:' + sg['id'],
                        'project.id:' + sg['tenant_id'], 'direction:' + d
                        ]
                self._statsd.gauge('networking.arista.security.groups', 0, tags=tags)
                try:
                    self._delete_acl_from_eos(name, s)
                except Exception as error:
                    msg = (_('Failed to delete ACL on EOS %s') % error)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)

    def apply_acl(self, sgs, switch_id=None, port_id=None, switch_info=None, server=None):
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

    def remove_acl(self, sgs, switch_id=None, port_id=None, switch_info=None, server=None):
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
            except Exception:
                msg = (_('Failed to remove ACL on port %s') % port_id)
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

        LOG.debug(_LI('Executing command on Arista EOS: %s'), full_command)

        try:
            # this returns array of return values for every command in
            # full_command list
            ret = server.runCmds(version=1, cmds=full_command)
            LOG.debug(_LI('Results of execution on Arista EOS: %s'), ret)

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

    def perform_sync_of_sg(self):
        """Perform sync of the security groups between ML2 and EOS.

        This is unconditional sync to ensure that all security
        ACLs are pushed to all the switches, in case of switch
        or neutron reboot
        """
        # Do nothing if Security Groups are not enabled

        if not self.sg_enabled:
            return

        self._maintain_connections()

        arista_ports = db_lib.get_ports()
        arista_port_ids = set(arista_ports.iterkeys())
        sg_bindings = self._ndb.get_all_security_gp_to_port_bindings(filters={'port_id': arista_port_ids})
        neutron_sgs = self._ndb.get_security_groups(
            filters={'id': set(binding['security_group_id'] for binding in sg_bindings)}
        )

        all_sgs = set()
        sgs_dict = collections.defaultdict(list)

        # Get the list of Security Groups of interest to us
        for s in sg_bindings:
            sgs_dict[s['port_id']].append(s['security_group_id'])

        for sgs in six.itervalues(sgs_dict):
            if sgs:
                all_sgs.add(tuple(sorted(sgs)))

        existing_acls = dict()
        active_acls = dict()
        for server_id, server in six.iteritems(self._server_by_id):
            active_acls_per_port = defaultdict(lambda: [None, None])
            active_acls[server_id] = active_acls_per_port
            try:
                acls, summary = server.runCmds(
                    version=1,
                    cmds=['show ip access-lists',
                          'show ip access-lists summary'])
                existing_acls[server_id] = {
                    acl['name']: acl['sequence']
                    for acl in acls['aclList']
                    if acl['name'].startswith('SG-')
                }
                for acl_list in summary['aclList']:
                    acl_name = acl_list['name']
                    for i, dir in enumerate(INTERFACE_DIRECTIONS):
                        for interface in acl_list[dir]:
                            if_name = interface['name']
                            active_acls_per_port[if_name][i] = acl_name
            except HTTPException:
                existing_acls[server_id] = {}

        # Create the ACLs on Arista Switches
        security_group_ips = {}
        known_acls = set()
        for sg_ids in all_sgs:
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
                known_acls.add(self._arista_acl_name(sg['id'], direction))
            self.create_acl(sg,
                            security_group_ips=security_group_ips,
                            existing_acls=existing_acls)

        # Get Baremetal port profiles, if any
        ports_by_switch = collections.defaultdict(dict)
        for bm in six.itervalues(db_lib.get_all_baremetal_ports()):
            sgs = sgs_dict.get(bm['port_id'], [])
            profile = json.loads(bm['profile'])
            link_info = profile['local_link_information']
            for l in link_info:
                if not l:
                    # skip all empty entries
                    continue
                switch = (l.get('switch_info'), l.get('switch_id'))
                ports_by_switch[switch][l['port_id']] = sgs

        for switch, port_security_groups in six.iteritems(ports_by_switch):
            server = self._get_server(*switch)
            if server is None:
                continue
            try:
                ret = server.runCmds(
                    version=1,
                    cmds=["show interfaces " +
                          ",".join(port_security_groups.iterkeys())])[0]
                for k, v in six.iteritems(ret['interfaces']):
                    pc = None
                    membership = v.get('interfaceMembership')
                    if membership:
                        pc = membership.rsplit(' ')[-1]

                    if pc not in port_security_groups:
                        port_security_groups[pc] = port_security_groups[k]
            except Exception:
                msg = (_('Failed to fetch interfaces from EOS %s') % s)
                LOG.exception(msg)
                continue

            acl_on_server = active_acls[server_id]
            for port_id, sgs in six.iteritems(port_security_groups):
                if sgs:
                    acl_on_port = acl_on_server[port_id]
                    if all(acl_on_port[i] == self._arista_acl_name(sgs, dir)
                           for i, dir in enumerate(DIRECTIONS)):
                        continue

                    self.apply_acl(sgs, server=server, port_id=port_id)
                else:
                    try:
                        self._run_openstack_sg_cmds([
                            'interface ' + port_id,
                            'ip access-group default in',
                            'no ip access-group default in',
                            'ip access-group default out',
                            'no ip access-group default out',
                            'exit'
                        ], server)
                    except arista_exc.AristaServicePluginRpcError as e:
                        pass

        for server_id, acls_on_switch in six.iteritems(existing_acls):
            unknown_acls = set(acls_on_switch.iterkeys()) - known_acls
            if not unknown_acls:
                continue

            LOG.warning("Orphaned ACL on %s: %s", server_id, unknown_acls)
            server = self._server_by_id[server_id]
            for name in unknown_acls:
                try:
                    self._delete_acl_from_eos(name, server)
                except Exception as error:
                    msg = (_('Failed to delete ACL on EOS: %s') % error)
                    LOG.exception(msg)
                    raise arista_exc.AristaSecurityGroupError(msg=msg)
