import math

import mock
from mock import patch
from netaddr import EUI

from networking_arista.common import config  # noqa
from oslo_config import cfg

from networking_arista.ml2 import arista_sec_gp
from networking_arista.common.exceptions import AristaSecurityGroupError
from neutron.tests.unit import testlib_api


def setup_config():
    cfg.CONF.set_override('sec_group_support', True, "ml2_arista")
    cfg.CONF.set_override('switch_info', ['switch1:user:pass'], "ml2_arista")
    cfg.CONF.set_override('consolidation_limit', 100, "ml2_arista")


class AristaSecGroupSwitchDriverTest(testlib_api.SqlTestCase):
    @patch("jsonrpclib.Server")
    def setUp(self, mock_json_server):
        super(AristaSecGroupSwitchDriverTest, self).setUp()
        setup_config()
        self.fake_rpc = mock.MagicMock()
        arista_sec_gp.db_lib = self.fake_rpc

        # Mock for maintain_connections
        mock_arista = mock_json_server.return_value
        mock_arista.runCmds.return_value = [{'chassisId': '01-23-45-67-89-01'}]

        self.drv = arista_sec_gp.AristaSecGroupSwitchDriver(self.fake_rpc)
        self.drv.ndb = mock.MagicMock()
        self.mock_sg_cmds = mock.MagicMock()
        self.drv._run_openstack_sg_cmds = self.mock_sg_cmds

    def test_consolidate_cmds(self):
        test_cmds = ["permit tcp host 10.180.1.%s any range 10000 10000 syn" % x for x in range(256)]
        test_cmds = test_cmds + ["permit tcp host 10.180.1.%s any range 10000 10000 syn" % x for x in range(4)]
        test_cmds = test_cmds + ["permit tcp host 10.181.%s.1 any range 10000 10000 syn" % x for x in range(10)]
        test_cmds = test_cmds + ["permit tcp host 10.180.1.%s any range 10002 10002 syn" % x for x in range(128)]
        test_cmds = test_cmds + ["permit udp host 10.180.1.%s any range ssh bittorrent syn" % x for x in range(128)]

        acls = self.drv._consolidate_cmds({'ingress': test_cmds, 'egress':[]})
        self.assertTrue(len(acls['ingress']) <= 13, 'Consolidation does not consolidate enough')

    @staticmethod
    def _get_sg_rule(protocol, remote_ip_prefix, port_range_min=22, port_range_max=1025):
        return {'protocol': protocol,
                'remote_ip_prefix': remote_ip_prefix,
                'remote_group_id': None,
                'port_range_min': port_range_min,
                'port_range_max': port_range_max,
                'direction': 'ingress'
               }

    def _get_existing_acls(self, sg_id):
        return {
            EUI('01-23-45-67-89-01'): {
                self.drv._arista_acl_name(sg_id, 'ingress'): [
                    {'text': 'permit tcp any any established'},
                    {'text': 'permit tcp 192.168.0.1/30 any range ssh blackjack syn'},
                    {'text': 'permit udp any eq bootps any eq bootpc'}
                ],
                self.drv._arista_acl_name(sg_id, 'egress'): [
                    {'text': 'permit tcp any any established'},
                    {'text': 'permit udp any eq bootpc any eq bootps'}
                ]
            }
        }

    def test_create_acl(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [self._get_sg_rule('tcp','192.168.0.1')]
             }

        self.mock_sg_cmds.reset_mock()
        self.drv.create_acl(sg)
        self.assertEqual(1, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertEqual([
            'ip access-list SG-IN-test_security_group',
            'permit tcp any any established',
            'permit tcp host 192.168.0.1 any range ssh blackjack syn',
            'permit udp any eq bootps any eq bootpc',
            'exit',
            'ip access-list SG-OUT-test_security_group',
            'permit tcp any any established',
            'permit udp any eq bootpc any eq bootps',
            'exit'
        ], self.mock_sg_cmds.call_args[0][0], "unexpected security group rules")

    def test_diff_create_acl(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [self._get_sg_rule('tcp','192.168.0.1/30')]
             }
        self.mock_sg_cmds.reset_mock()
        self.drv.create_acl(sg, None, self._get_existing_acls(sg['id']))
        self.mock_sg_cmds.assert_not_called()

        sg['security_group_rules'][0] = self._get_sg_rule('udp', '192.168.0.1/30')
        self.drv.create_acl(sg, None, self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertIn('no permit tcp 192.168.0.1/30 any range ssh blackjack syn',
                      self.mock_sg_cmds.call_args[0][0], 'Excepted delete rule')
        self.assertIn('permit udp 192.168.0.1/30 any range ssh blackjack',
                      self.mock_sg_cmds.call_args[0][0], 'Excepted new rule')

    def test_diff_alot_sgs(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules': [
                  self._get_sg_rule('udp', '192.168.{0}.{1}'.format(int(math.floor(r / 256)), r % 256)) for r in range(1, 256*256)
              ] + [self._get_sg_rule('tcp', '192.168.32.3/28')] + [self._get_sg_rule('udp', '192.168.32.3/28')]
             }
        self.mock_sg_cmds.reset_mock()
        self.drv.create_acl(sg, None, self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertTrue(len(self.mock_sg_cmds.call_args[0][0]) < 100, 'Consolidation doesnt work')

    def test_allow_all(self):
        sg = {'id': 'test_security_group',
              'tenant_id': '123456789',
              'security_group_rules':
                  [ self._get_sg_rule('udp', '192.168.{0}.{1}'.format(int(math.floor(r / 256)), r % 256))
                    for r in range(1, 256 * 256) ] +
                  [self._get_sg_rule('udp', '192.168.32.3/28')] + [self._get_sg_rule('udp', '0.0.0.0/0')]
             }
        self.mock_sg_cmds.reset_mock()
        self.drv.create_acl(sg, None, self._get_existing_acls(sg['id']))
        self.assertEqual(1, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertEqual(9, len(self.mock_sg_cmds.call_args[0][0]), 'Expected only 9 rules')
        self.assertIn('permit udp 0.0.0.0/0 any range ssh blackjack ',
                      self.mock_sg_cmds.call_args[0][0], 'Expected all network rule')
        self.assertIn('permit udp any 0.0.0.0/0 range ssh blackjack ',
                      self.mock_sg_cmds.call_args[0][0], 'Excepted all network rule')

    def test_icmp(self):
        def _get_sg(from_port, to_port):
            return {'id': u'test_icmp_sg',
                  'tenant_id': '123456789',
                  'security_group_rules': [
                      self._get_sg_rule('icmp', 'any', from_port, to_port)
                  ]
                  }
        self.mock_sg_cmds.reset_mock()
        self.drv.create_acl(_get_sg(None, None), None, None)
        self.assertEqual(1, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertIn('permit icmp any any', self.mock_sg_cmds.call_args[0][0],
                      'expected generic ICMP rule')

        self.drv.create_acl(_get_sg(1, None), None, None)
        self.assertEqual(2, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertIn('permit icmp any any 1', self.mock_sg_cmds.call_args[0][0],
                      'expected ICMP rule with type')

        self.drv.create_acl(_get_sg(2, 3), None, None)
        self.assertEqual(3, self.mock_sg_cmds.call_count, "expected to be called once")
        self.assertIn('permit icmp any any 2 3', self.mock_sg_cmds.call_args[0][0],
                      'expected ICMP rule with type and rule')

        self.assertRaisesRegexp(AristaSecurityGroupError, 'Invalid ICMP rule specified',
                                self.drv.create_acl, _get_sg(None, 666), None, None)