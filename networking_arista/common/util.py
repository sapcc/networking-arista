# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import string

import netaddr
import requests
import six

from collections import defaultdict
from intervaltree import IntervalTree
from networking_arista.common import constants
from oslo_config import cfg
from oslo_serialization.jsonutils import loads
from oslo_utils.importutils import try_import
from six.moves.urllib_parse import urlparse

LOG = logging.getLogger(__name__)

cfg.CONF.import_group('ml2_arista', 'networking_arista.common.config')

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


def measure_hook(r, *args, **kwargs):
    r.hook_called = True
    try:
        host = urlparse(r.url).hostname
        cmds = loads(r.request.body)['params']['cmds']
        if len(cmds) == 1:
            cmd = cmds[0].replace(' ', '_')
        else:  # First two are enable & configure
            cmd = cmds[2].split(' ')
            if cmd[-1].startswith('SG-'):
                cmd.pop()
            cmd = ' '.join('_')
        STATS.timing('networking.arista.request', r.elapsed.total_seconds(),
                     tags=['host:' + host,
                           'cmd:' + cmd],
                     sample_rate=60.0,
                     )
    except (AttributeError, KeyError):
        pass
    return r


def make_http_session():
    s = requests.session()
    max_connections = cfg.CONF.ml2_arista.max_connections
    max_pools = cfg.CONF.ml2_arista.max_pools
    max_retries = cfg.CONF.ml2_arista.max_retries
    pool_block = cfg.CONF.ml2_arista.http_pool_block

    s.headers['Content-Type'] = 'application/json'
    s.headers['Accept'] = 'application/json'
    if cfg.CONF.ml2_arista.http_connection_close:
        s.headers['Connection'] = 'close'

    s.verify = cfg.CONF.ml2_arista.verify_ssl
    retry = requests.packages.urllib3.util.retry.Retry(
        total=max_retries,
        method_whitelist=False,  # Most RPC Calls are POST, and idempotent
        backoff_factor=0.3,
    )
    s.mount('https://', requests.adapters.HTTPAdapter(
        max_retries=retry,
        pool_connections=max_pools,
        pool_maxsize=max_connections,
        pool_block=pool_block,
    ))
    s.mount('http://', requests.adapters.HTTPAdapter(
        max_retries=retry,
        pool_connections=max_pools,
        pool_maxsize=max_connections,
        pool_block=pool_block,
    ))

    if dogstatsd:
        s.hooks['response'].append(measure_hook)

    return s


class PartialFormatter(string.Formatter):
    def __init__(self, missing='', bad_fmt=''):
        self.missing = missing
        self.bad_fmt = bad_fmt

    def get_field(self, field_name, args, kwargs):
        # Handle a key not found
        try:
            val = super(PartialFormatter, self).get_field(field_name,
                                                          args, kwargs)
            # Python 3, 'super().get_field(field_name, args, kwargs)' works
        except (KeyError, AttributeError):
            val = None, field_name
        return val

    def format_field(self, value, spec):
        # handle an invalid format
        if value is None:
            return self.missing

        try:
            return super(PartialFormatter, self).format_field(value, spec)
        except ValueError:
            if self.bad_fmt is not None:
                return self.bad_fmt
            else:
                raise


def _try_merge_rules(rule0, rule1):
    if rule0.get('protocol') not in ('tcp', 'udp', 'icmp'):
        return

    if rule1.get('protocol') not in ('tcp', 'udp', 'icmp'):
        return

    is_icmp = rule1.get('protocol') == 'icmp'

    group0 = rule0.get('remote_group_id')
    group1 = rule1.get('remote_group_id')
    prefix0 = rule0.get('remote_ip_prefix')
    prefix1 = rule1.get('remote_ip_prefix')

    merged_nets = None
    if prefix0 is not None and prefix1 is not None:
        merged_nets = netaddr.cidr_merge([prefix0, prefix1])

        if len(merged_nets) == 2:
            return

    same_net = (group0 and group0 == group1
                or merged_nets and prefix0 == prefix1)

    rule0_min = rule0.get('port_range_min')
    rule0_max = rule0.get('port_range_max')
    rule1_min = rule1.get('port_range_min')
    rule1_max = rule1.get('port_range_max')

    if not is_icmp:
        rule0_min = rule0_min or 0
        rule0_max = rule0_max or 65535
        rule1_min = rule1_min or 0
        rule1_max = rule1_max or 65535

        if rule0_max + 1 < rule1_min or rule1_max + 1 < rule0_min:
            return

    same_ports = rule0_min == rule1_min and rule0_max == rule1_max

    # This will merge adjacent port-ranges (in same networks)
    if same_net and not is_icmp:
        rule_min = min(rule0_min, rule1_min)
        rule_max = max(rule0_max, rule1_max)
        if rule_min == 0 and rule_max == 65535:
            rule_min = None
            rule_max = None

        rule0['port_range_min'] = rule_min
        rule0['port_range_max'] = rule_max
        return rule0

    # This will merge adjacent networks (with same port ranges)
    if same_ports:
        rule0['remote_ip_prefix'] = merged_nets[0]
        return rule0

    # We have an overlap of ports and networks, but we can only merge them
    # If one is contained in the other

    net1_in_net0 = (merged_nets and prefix1 in prefix0
                    or prefix0 and prefix0.prefixlen == 0)

    ports1_in_ports0 = (
            not is_icmp and rule1_min >= rule0_min and rule1_max <= rule0_max
            or is_icmp and rule0_min is None and rule0_max is None
    )

    if net1_in_net0 and ports1_in_ports0:
        # rule1 is fully contained in rule0
        return rule0

    net0_in_net1 = (merged_nets and prefix0 in prefix1
                    or prefix1 and prefix1.prefixlen == 0)

    ports0_in_ports1 = (
            not is_icmp and rule0_min >= rule1_min and rule0_max <= rule1_max
            or is_icmp and rule1_min is None and rule1_max is None
    )
    if net0_in_net1 and ports0_in_ports1:
        for k, v in six.iteritems(rule1):
            rule0[k] = v
        return rule0

    return


def optimize_security_group_rules(rules):
    grouped_rules = defaultdict(
        lambda: (defaultdict(list),  # Keyed by sg, cannot merge across sgs
                 IntervalTree())  # Keyed by ip-range
    )
    for rule in rules:
        ethertype = rule['ethertype']
        sg_list, ip_tree = grouped_rules[(rule['direction'],
                                          ethertype,
                                          rule['protocol'])]

        rule = dict(rule)  # Work with a copy, modifying rule in place
        remote_group_id = rule['remote_group_id']
        if remote_group_id:
            # We can only merge security groups of the same id, or...
            group = sg_list[remote_group_id]
            merged = None
            for orule in group:
                merged = _try_merge_rules(orule, rule)
                if merged:
                    break

            net = constants.ANY_NET[ethertype]
            # Net-ranges covering any ip
            for orule in [i.data for i in ip_tree.search(net.first)
                          if i.data['remote_ip_prefix'] == net]:
                merged = _try_merge_rules(orule, rule)
                if merged:
                    break

            if not merged:
                group.append(rule)
        else:
            remote_ip_prefix = rule['remote_ip_prefix']
            if remote_ip_prefix and remote_ip_prefix != 'any':
                net = netaddr.IPNetwork(remote_ip_prefix)
            else:
                net = constants.ANY_NET[ethertype]
            rule['remote_ip_prefix'] = net
            begin = net.first
            end = net.last + 2  # Otherwise it doesn't merge .0/25, .128/25

            while True:
                # We will break the loop, when we do not find any rule to merge
                # The else case will add then the rule
                for orule in ip_tree.search(begin, end):
                    ip_tree.remove(orule)
                    merged = _try_merge_rules(orule.data, rule)
                    if merged:
                        rule = merged
                        net = merged['remote_ip_prefix']
                        begin = net.first
                        end = net.last + 2
                        break  # Restart with the merged rule
                    else:
                        ip_tree.add(orule)
                else:
                    ip_tree.addi(begin, end, rule)
                    break

            if net.prefixlen == 0:
                for orules in six.itervalues(sg_list):
                    # Filter out all rules, which fit the given rule
                    orules[:] = [orule for orule in orules
                                 if not _try_merge_rules(orule, rule)]

    output = []
    for sg_list, ip_tree in six.itervalues(grouped_rules):
        for rl in six.itervalues(sg_list):
            for r in rl:
                output.append(r)
        for ri in ip_tree:
            r = ri.data
            remote_ip_prefix = r['remote_ip_prefix']
            if remote_ip_prefix:
                r['remote_ip_prefix'] = str(remote_ip_prefix)
            output.append(r)

    return output


def get_attr_or_item(obj, key):
    if hasattr(obj, key):
        return getattr(obj, key)
    else:
        return obj[key]
