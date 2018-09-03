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

import collections
import logging
import netaddr
import os
import requests
import six
import string

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
        return False

    if rule1.get('protocol') not in ('tcp', 'udp', 'icmp'):
        return False

    is_icmp = rule1.get('protocol') == 'icmp'

    group0 = rule0.get('remote_group_id')
    group1 = rule1.get('remote_group_id')
    prefix0 = rule0.get('remote_ip_prefix')
    prefix1 = rule1.get('remote_ip_prefix')
    net0 = prefix0 and netaddr.IPNetwork(prefix0)
    net1 = prefix1 and netaddr.IPNetwork(prefix1)

    merged_nets = None
    if net0 is not None and net1 is not None:
        merged_nets = netaddr.cidr_merge([net0, net1])

        if len(merged_nets) == 2:
            return False

    same_net = (group0 and group0 == group1
                or merged_nets and net0 == net1)

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
            return False

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
        return True

    # This will merge adjacent networks (with same port ranges)
    if same_ports:
        rule0['remote_ip_prefix'] = str(merged_nets[0])
        return True

    # We have an overlap of ports and networks, but we can only merge them
    # If one is contained in the other

    net1_in_net0 = (merged_nets and net1 in net0
                    or net0 and net0.prefixlen == 0)

    ports1_in_ports0 = (
            not is_icmp and rule1_min >= rule0_min and rule1_max <= rule0_max
            or is_icmp and rule0_min is None and rule0_max is None
    )

    if net1_in_net0 and ports1_in_ports0:
        # rule1 is fully contained in rule0
        return True  # Nothing to be done

    net0_in_net1 = (merged_nets and net0 in net1
                    or net1 and net1.prefixlen == 0)

    ports0_in_ports1 = (
            not is_icmp and rule0_min >= rule1_min and rule0_max <= rule1_max
            or is_icmp and rule1_min is None and rule1_max is None
    )
    if net0_in_net1 and ports0_in_ports1:
        for k, v in six.iteritems(rule1):
            rule0[k] = v
        return True

    return False


def optimize_security_group_rules(rules):
    grouped_rules = collections.defaultdict(list)
    for rule in rules:
        group = grouped_rules[(rule['direction'],
                               rule['ethertype'],
                               rule['protocol'])]
        for orule in group:
            if _try_merge_rules(orule, rule):
                break
        else:
            group.append(dict(rule))  # Copy, as we will merge the rules

    output = []
    for g in six.itervalues(grouped_rules):
        for r in g:
            output.append(r)

    return output
