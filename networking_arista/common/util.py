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

from oslo_config import cfg
import requests

cfg.CONF.import_group('ml2_arista', 'networking_arista.common.config')


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

    return s
