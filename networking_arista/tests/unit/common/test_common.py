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


from networking_arista.common.util import optimize_security_group_rules
from networking_arista.tests import base

GROUP_ID = 'GROUP-1'
GROUP_ID_OTHER = 'GROUP-2'


class TestNetworkingCommonOptimizeSecurityGroupRules(base.TestCase):
    def test_optimize_security_group_rules_empty(self):
        res = optimize_security_group_rules([])
        self.assertEqual(res, [])

    def test_combine_adjacent_port_ranges_negative(self):
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 55,
                  'remote_group_id': GROUP_ID,
                  'remote_ip_prefix': None,
                  'port_range_min': 52, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': GROUP_ID_OTHER,
                  'remote_ip_prefix': None,
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': 56,
                   'remote_group_id': GROUP_ID,
                   'remote_ip_prefix': None,
                   'port_range_min': 52, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.failIfEqual(sorted(res), sorted(output))

    def test_combine_adjacent_port_ranges(self):
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 54,
                  'remote_group_id': GROUP_ID,
                  'remote_ip_prefix': None,
                  'port_range_min': 52, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': GROUP_ID,
                  'remote_ip_prefix': None,
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': 56,
                   'remote_group_id': GROUP_ID,
                   'remote_ip_prefix': None,
                   'port_range_min': 52, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_any_port_range(self):
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': None,
                  'remote_group_id': GROUP_ID,
                  'remote_ip_prefix': None,
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': GROUP_ID,
                  'remote_ip_prefix': None,
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': None,
                   'remote_group_id': GROUP_ID,
                   'remote_ip_prefix': None,
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_subnets_failure(self):
        # We cannot merge adjacent subnets, if the ports differ
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': None,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/25',
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.128/25',
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.0/25',
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  {'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': 56,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.128/25',
                   'port_range_min': 55, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_adjacent_subnets(self):
        # We can merge adjacent subnets, if the ports are the same
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/25',
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.128/25',
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': 56,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.0/24',
                   'port_range_min': 55, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_containing_subnets(self):
        # We can merge adjacent subnets, one is a subset of the other
        # in both ports and subnet
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': None,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/24',
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/25',
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.0/24',
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_containing_groups_ipv4(self):
        # We can merge adjacent subnets, one is a subset of the other
        # in both ports and subnet
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': None,
                  'remote_group_id': None,
                  'remote_ip_prefix': '0.0.0.0/0',
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': GROUP_ID_OTHER,
                  'remote_ip_prefix': None,
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '0.0.0.0/0',
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_containing_groups_ipv6(self):
        # We can merge adjacent subnets, one is a subset of the other
        # in both ports and subnet
        input = [{'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': None,
                  'remote_group_id': None,
                  'remote_ip_prefix': '::/0',
                  'port_range_min': None, 'ethertype': u'IPv6'},
                 {'direction': 'ingress', 'protocol': u'tcp',
                  'port_range_max': 56,
                  'remote_group_id': GROUP_ID_OTHER,
                  'remote_ip_prefix': None,
                  'port_range_min': 55, 'ethertype': u'IPv6'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'tcp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '::/0',
                   'port_range_min': None, 'ethertype': u'IPv6'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_containing_subnets_icmp(self):
        # We can merge adjacent subnets, one is a subset of the other
        # in both ports and subnet
        input = [{'direction': 'ingress', 'protocol': u'icmp',
                  'port_range_max': None,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/24',
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'icmp',
                  'port_range_max': 56,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/25',
                  'port_range_min': 55, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'icmp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.0/24',
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.assertItemsEqual(res, output)

        res = optimize_security_group_rules(reversed(input))
        self.assertItemsEqual(res, output)

    def test_combine_containing_subnets_icmp_fail(self):
        # We can merge adjacent subnets, one is a subset of the other
        # in both ports and subnet
        input = [{'direction': 'ingress', 'protocol': u'icmp',
                  'port_range_max': 1,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/24',
                  'port_range_min': None, 'ethertype': u'IPv4'},
                 {'direction': 'ingress', 'protocol': u'icmp',
                  'port_range_max': 5,
                  'remote_group_id': None,
                  'remote_ip_prefix': '192.0.2.0/25',
                  'port_range_min': 1, 'ethertype': u'IPv4'},
                 ]
        output = [{'direction': 'ingress', 'protocol': u'icmp',
                   'port_range_max': None,
                   'remote_group_id': None,
                   'remote_ip_prefix': '192.0.2.0/24',
                   'port_range_min': None, 'ethertype': u'IPv4'},
                  ]

        res = optimize_security_group_rules(input)
        self.failIf(res == output)

        res = optimize_security_group_rules(reversed(input))
        self.failIf(res == output)
