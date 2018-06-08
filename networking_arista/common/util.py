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

import requests


def make_http_session(max_pools=16, max_connections=1,
                      pool_block=True, max_retries=5):
    s = requests.session()
    s.headers['Content-Type'] = 'application/json'
    s.headers['Accept'] = 'application/json'
    s.verify = False
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
