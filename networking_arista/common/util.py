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
from oslo_config import cfg
from oslo_serialization.jsonutils import loads
from oslo_utils.importutils import try_import
import requests
from six.moves.urllib_parse import urlparse
import string

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
