# Copyright 2014 Arista Networks, Inc.  All rights reserved.
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


import json
import mock
import os

from collections import defaultdict
from netaddr import EUI
from neutron.context import get_admin_context
from neutron.tests.unit import testlib_api
from oslo_config import cfg

from networking_arista.common.exceptions import AristaSecurityGroupError
from networking_arista.ml2 import arista_sec_gp


def setup_config():
    cfg.CONF.set_override('sec_group_support', True, 'ml2_arista')
    cfg.CONF.set_override('switch_info', ['switch1:user:pass'], 'ml2_arista')
    cfg.CONF.set_override('lossy_consolidation_limit', 100, 'ml2_arista')
    cfg.CONF.set_override('sec_group_background_only', False, 'ml2_arista')
    cfg.CONF.set_override('skip_unplug', False, 'ml2_arista')
    cfg.CONF.set_override('coordinator_url', None, 'ml2_arista')


def fake_send_eapi_req(url, cmds):
    ret = []
    for cmd in cmds:
        if 'show lldp local-info management 1' == cmd:
            if 'switch2' in url:
                ret.append({'chassisId': '02-34-56-78-90-12'})
            else:
                ret.append({'chassisId': '01-23-45-67-89-01'})
        elif 'show ip access-lists' == cmd:
            cur_dir = os.path.dirname(os.path.realpath(__file__))
            ret.append(json.load(open(cur_dir + '/jsonrpc.json')))

            # add make some diff between routers
            if 'switch2' in url:
                ret[len(ret) - 1]['aclList'][0]['sequence'] = []
        elif 'show ip access-lists summary' == cmd:
            ret.append({'aclList': [
                {'name': 'SG-IN-test_security_group',
                 'configuredEgressIntfs': [],
                 'configuredIngressIntfs': []}
            ]})
        else:
            ret.append(None)
    return ret


def no_optimize(rules):
    return rules


class AristaSecGroupSwitchDriverTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(AristaSecGroupSwitchDriverTest, self).setUp()
        setup_config()
        self.fake_rpc = mock.MagicMock()
        arista_sec_gp.AristaSwitchRPCMixin._SERVER_BY_ID = dict()
        arista_sec_gp.AristaSwitchRPCMixin._SERVER_BY_IP = dict()
        arista_sec_gp.AristaSwitchRPCMixin._INTERFACE_MEMBERSHIP = \
            defaultdict(dict)

        patcher = mock.patch('networking_arista.ml2.mechanism_arista.db_lib',
                             new=self.fake_rpc).start()
        self.addCleanup(patcher.stop)

        self.drv = arista_sec_gp.AristaSecGroupSwitchDriver(self.fake_rpc)
        self.drv._send_eapi_req = fake_send_eapi_req
        self.mock_sg_cmds = mock.MagicMock()
        self.drv._run_openstack_sg_cmds = self.mock_sg_cmds
        self.drv._maintain_connections()

    def test_consolidaterule_cmds(self):
        self.drv.max_rules = 100
        consolidation_target = {
            'tcp': 10,
            'udp': 12,
            'icmp': 9,
        }

        for proto in ('tcp', 'udp', 'icmp'):
            has_ports = proto != 'icmp'
            if has_ports:
                high_port = 10000
                port_min = 22
                port_max = 6969
            else:
                high_port = None
                port_min = None
                port_max = None

            sg = {
                'id': 'test_security_group',
                'tenant_id': '123456789',
                'security_group_rules':
                    [self._get_sg_rule(
                        proto,
                        '10.180.1.%s' % x,
                        high_port,
                        high_port)
                        for x in range(0, 256)] +
                    [self._get_sg_rule(
                        proto,
                        '10.180.1.%s' % x,
                        high_port,
                        high_port) for x in range(0, 4)] +
                    [self._get_sg_rule(
                        proto,
                        '10.180.1.%s' % x,
                        port_min,
                        port_max)
                        for x in range(0, 128)]
            }

            self.mock_sg_cmds.reset_mock()
            context = get_admin_context()
            self.drv.create_acl(context, sg)
            self.assertEqual(1, self.mock_sg_cmds.call_count,
                             'expected to be called once')

            self.assertEqual(
                consolidation_target[proto],
                len(self.mock_sg_cmds.call_args[0][0]),
                'insufficient consolidation for protocol %s' % proto
            )

            if has_ports:
                flags = ' syn' if proto == 'tcp' else ''
                self.assertTrue(
                    ('permit %s 10.180.1.0/24 any range 10000 10000%s'
                     % (proto, flags))
                    in self.mock_sg_cmds.call_args[0][0],
                    'Missing consolidated 10.180.1.0/24 subnet for %s'
                    % proto
                )
                self.assertTrue(
                    ('permit %s 10.180.1.0/25 any range 22 6969%s'
                     % (proto, flags))
                    in self.mock_sg_cmds.call_args[0][0],
                    'Missing consolidated 10.180.1.0/25 subnet for %s'
                    % proto
                )
            else:
                self.assertTrue(
                    ('permit %s 10.180.1.0/24 any'
                     % proto)
                    in self.mock_sg_cmds.call_args[0][0],
                    'Missing consolidated 10.180.1.0/24 subnet for %s'
                    % proto
                )

    def test_consolidate_rule_cmds_max(self):
        consolidation_target = {
            'tcp': 9,
            'udp': 10,
            'icmp': 9,
        }

        for proto in ('udp', 'tcp', 'icmp'):
            self.drv.max_rules = 1
            has_ports = proto != 'icmp'
            if has_ports:
                high_port = 10000
            else:
                high_port = None

            sg = {
                'id': 'test_security_group',
                'tenant_id': '123456789',
                'security_group_rules':
                    [self._get_sg_rule(proto,
                                       '10.180.1.1',
                                       high_port,
                                       high_port)] +
                    [self._get_sg_rule(proto,
                                       '192.168.1.1',
                                       high_port,
                                       high_port)]
            }

            self.mock_sg_cmds.reset_mock()
            context = get_admin_context()
            self.drv.create_acl(context, sg)
            self.assertEqual(1, self.mock_sg_cmds.call_count,
                             'expected to be called once')

            self.assertEqual(
                consolidation_target[proto],
                len(self.mock_sg_cmds.call_args[0][0]),
                'insufficient consolidation for protocol %s' % proto
            )

            if has_ports:
                flags = ' syn' if proto == 'tcp' else ''
                self.assertTrue(
                    ('permit %s any any range 10000 10000%s'
                     % (proto, flags))
                    in self.mock_sg_cmds.call_args[0][0],
                    'Missing consolidated 10.180.1.0/24 subnet for %s'
                    % proto
                )
            else:
                self.assertTrue(
                    ('permit %s any any'
                     % proto)
                    in self.mock_sg_cmds.call_args[0][0],
                    'Missing consolidated any subnet for %s'
                    % proto
                )
        self.drv.max_rules = 100

    @staticmethod
    def _get_sg_rule(protocol, remote_ip_prefix, port_range_min=22,
                     port_range_max=1025, direction='ingress'):
        return {'protocol': protocol,
                'ethertype': 'IPv4',
                'remote_ip_prefix': remote_ip_prefix,
                'remote_group_id': None,
                'port_range_min': port_range_min,
                'port_range_max': port_range_max,
                'direction': direction
                }

    def _get_existing_acls(self, sg_id, server_id=EUI('01-23-45-67-89-01')):
        return {
            self.drv._SERVER_BY_ID[server_id]: {
                self.drv._arista_acl_name(sg_id, 'ingress'): [
                    {'text': 'permit tcp any any established',
                     'sequenceNumber': 10},
                    {'text': 'permit udp any eq 67 any eq 68',
                     'sequenceNumber': 20},
                    {'text': 'permit tcp 192.168.0.1/30 any '
                             'range 22 1025 syn',
                     'sequenceNumber': 30},
                ],
                self.drv._arista_acl_name(sg_id, 'egress'): [
                    {'text': 'permit tcp any any established',
                     'sequenceNumber': 10},
                    {'text': 'permit udp any eq 68 any eq 67',
                     'sequenceNumber': 20},
                ]
            }
        }

    def test_create_acl(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [self._get_sg_rule('tcp', '192.168.0.1')]
              }

        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, sg)
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertListEqual([
            'ip access-list SG-IN-test_security_group',
            'permit tcp any any established',
            'permit udp any eq 67 any eq 68',
            'permit tcp host 192.168.0.1 any range 22 1025 syn',
            'exit',
            'ip access-list SG-OUT-test_security_group',
            'permit tcp any any established',
            'permit udp any eq 68 any eq 67',
            'exit'
        ], self.mock_sg_cmds.call_args[0][0],
            'unexpected security group rules')

    def test_diff_create_acl(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [
                  self._get_sg_rule('tcp', '192.168.0.1/30')]
              }
        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        existing_acls = self._get_existing_acls(sg['id'])
        self.drv.create_acl(context, sg, None, existing_acls)
        self.mock_sg_cmds.assert_not_called()

        sg['security_group_rules'][0] = self._get_sg_rule('udp',
                                                          '192.168.0.1/30')
        self.drv.create_acl(context, sg, None,
                            self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertIn('no 30',
                      self.mock_sg_cmds.call_args[0][0],
                      'Excepted delete rule')
        self.assertIn('permit udp 192.168.0.1/30 any range 22 1025',
                      self.mock_sg_cmds.call_args[0][0], 'Excepted new rule')

    @mock.patch('networking_arista.common.util.optimize_security_group_rules',
                side_effect=no_optimize)
    def test_diff_alot_sgs(self, optimizer):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules':
                  [self._get_sg_rule('udp', '192.168.{0}.{1}'.format(i, j))
                   for i in range(0, 256) for j in range(0, 256)
                   ] + [self._get_sg_rule('tcp', '192.168.32.3/28')] +
                  [self._get_sg_rule('udp', '192.168.32.3/28')]
              }
        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, sg, None,
                            self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertTrue(len(self.mock_sg_cmds.call_args[0][0]) < 100,
                        "Consolidation doesn't work")

    def test_allow_all(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules':
                  [self._get_sg_rule('udp', '192.168.{0}.1'.format(j))
                   for j in range(0, 256)] +
                  [self._get_sg_rule('udp', '192.168.32.3/28')] + [
                      self._get_sg_rule('udp', '0.0.0.0/0')]
              }
        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, sg, None,
                            self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertEqual(7, len(self.mock_sg_cmds.call_args[0][0]),
                         'Expected only 9 rules')
        self.assertIn('permit udp any any range 22 1025',
                      self.mock_sg_cmds.call_args[0][0],
                      'Expected all network rule')
        self.assertIn('permit udp any any range 22 1025',
                      self.mock_sg_cmds.call_args[0][0],
                      'Excepted all network rule')

    def test_icmp(self):
        def _get_sg(from_port, to_port):
            return {'id': u'test_icmp_sg',
                    'tenant_id': '123456789',
                    'security_group_rules': [
                        self._get_sg_rule('icmp', 'any', from_port, to_port)
                    ]
                    }

        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, _get_sg(None, None), None, None)
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertIn('permit icmp any any', self.mock_sg_cmds.call_args[0][0],
                      'expected generic ICMP rule')

        self.drv.create_acl(context, _get_sg(1, None), None, None)
        self.assertEqual(2, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertIn('permit icmp any any 1',
                      self.mock_sg_cmds.call_args[0][0],
                      'expected ICMP rule with type')

        self.drv.create_acl(context, _get_sg(2, 3), None, None)
        self.assertEqual(3, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertIn('permit icmp any any 2 3',
                      self.mock_sg_cmds.call_args[0][0],
                      'expected ICMP rule with type and rule')

        self.assertRaisesRegex(AristaSecurityGroupError,
                               'Invalid ICMP rule specified',
                               self.drv.create_acl, context,
                               _get_sg(None, 666), None, None)

    def test_periodic_sync(self):
        self.mock_sg_cmds.reset_mock()
        context = self.mock_port([self._get_sg_rule('tcp', '192.168.0.1')])
        self.drv.perform_sync_of_sg(context)
        # One for creating the group, another one for applying it to the port
        self.assertEqual(2, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertListEqual([
            'ip access-list SG-IN-test_security_group',
            'permit tcp host 192.168.0.1 any range 22 1025 syn',
            'no 30',
            'no 90',
            'no 100',
            'no 110',
            'no 120',
            'no 130',
            'no 140',  # This one is a duplicate
            'exit',
            'ip access-list SG-OUT-test_security_group',
            'no 20',
            'no 30',
            'no 60',
            'no 70',
            'exit'],
            self.mock_sg_cmds.call_args_list[0][0][0],
            'unexpected security group rules')

        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [
                  self._get_sg_rule(None, '100.100.0.0/16', None, None)]
              }
        self.fake_rpc.get_security_groups.return_value = {
            'test_security_group': sg}
        self.mock_sg_cmds.reset_mock()
        self.drv.perform_sync_of_sg(context)
        self.assertListEqual([
            'ip access-list SG-IN-test_security_group',
            'permit icmp 100.100.0.0/16 any',
            'no 30',
            'no 100',
            'no 110',
            'no 130',
            'no 140',  # This one is a duplicate
            'exit',
            'ip access-list SG-OUT-test_security_group',
            'no 20',
            'no 30',
            'no 70',
            'exit'],
            self.mock_sg_cmds.call_args_list[0][0][0],
            'unexpected security group rules')

    def test_async_switches(self):
        cfg.CONF.set_override('switch_info',
                              ['switch1:user:pass', 'switch2:user:pass'],
                              'ml2_arista')

        context = self.mock_port([self._get_sg_rule('tcp', '192.168.0.2')])
        self.mock_sg_cmds.reset_mock()

        self.drv.perform_sync_of_sg(context)
        # One for creating the security group, the second for applying it to
        # the port
        self.assertEqual(2, self.mock_sg_cmds.call_count,
                         'expected to be called twice')
        self.assertListEqual([
            'ip access-list SG-IN-test_security_group',
            'permit tcp host 192.168.0.2 any range 22 1025 syn',
            'no 30',
            'no 90',
            'no 100',
            'no 110',
            'no 120',
            'no 130',
            'no 140',  # This one is a duplicate
            'exit',
            'ip access-list SG-OUT-test_security_group',
            'no 20',
            'no 30',
            'no 60',
            'no 70',
            'exit'],
            self.mock_sg_cmds.call_args_list[0][0][0],
            'unexpected security group rules on Switch 1')
        self.assertListEqual([
            'interface portx',
            'ip access-group SG-IN-test_security_group out',
            'exit',
            'interface portx',
            'ip access-group SG-OUT-test_security_group in',
            'exit'],
            self.mock_sg_cmds.call_args_list[1][0][0],
            'unexpected security group rules on Switch 2')

    def mock_port(self, rules=[]):
        port_id = 'PORTID123456789'
        port = {
            'port_id': port_id,
            'security_group_id': 'test_security_group',
            'profile': {
                'local_link_information': [
                    {'switch_info': 'switch1',
                     'switch_id': '01-23-45-67-89-01',
                     'port_id': 'portx'
                     },
                ]
            }
        }
        sg = {
            'id': 'test_security_group',
            'tenant_id': '123456789',
            'security_group_rules': rules
        }
        self.fake_rpc.get_all_security_gp_to_port_bindings.return_value = [
            port
        ]
        self.fake_rpc.get_security_groups.return_value = {
            'test_security_group': sg
        }
        context = mock.MagicMock()
        context.session.query.return_value. \
            filter_by.return_value. \
            all.return_value = [mock.MagicMock(**port)]
        return context

    def test_ipv6_duplicated_acls(self):
        sg = {
            'tenant_id': 'test_tenant',
            'id': 'test_security_group', 'security_group_rules': [
                {'direction': 'egress', 'protocol': None,
                 'port_range_max': None,
                 'id': '2187a27a-8bd2-40c9-897a-4265f2c91745',
                 'remote_group_id': None, 'remote_ip_prefix': None,
                 'security_group_id': 'test_security_group',
                 'tenant_id': 'test_tennant', 'port_range_min': None,
                 'ethertype': 'IPv4'},
                {'direction': 'egress', 'protocol': None,
                 'port_range_max': None,
                 'id': '2187a27a-8bd2-40c9-897a-4265f2c91745',
                 'remote_group_id': None, 'remote_ip_prefix': None,
                 'security_group_id': 'test_security_group',
                 'tenant_id': 'test_tenant', 'port_range_min': None,
                 'ethertype': 'IPv6'}], 'name': 'default'}
        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, sg)
        cmds = self.mock_sg_cmds.call_args_list[0][0][0]
        # + 2 for EXIT and Security Group preamble
        self.assertEqual(len(list(set(cmds))) + 2, len(cmds),
                         'unexpected duplicate entries')

    def test_duplicate_rules_are_no_longer_treated_idempotently(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [
                  self._get_sg_rule('tcp', '192.168.0.1/30')]
              }
        self.mock_sg_cmds.reset_mock()
        context = get_admin_context()
        self.drv.create_acl(context, sg, None,
                            self._get_existing_acls(sg['id']))
        self.mock_sg_cmds.assert_not_called()

        sg['security_group_rules'][0] = self._get_sg_rule('udp',
                                                          '192.168.0.1/30')
        self.drv.create_acl(context, sg, None,
                            self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count,
                         'expected to be called once')
        self.assertNotIn('permit tcp any any established',
                         self.mock_sg_cmds.call_args[0][0])
