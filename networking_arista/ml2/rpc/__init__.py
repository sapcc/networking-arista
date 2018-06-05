# Copyright (c) 2018 OpenStack Foundation
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

from networking_arista.common.exceptions import AristaConfigError
from networking_arista.ml2.rpc.arista_eapi import AristaRPCWrapperEapi
from networking_arista.ml2.rpc.arista_json import AristaRPCWrapperJSON
from networking_arista.ml2.rpc.arista_nocvx import AristaRPCWrapperNoCvx


def get_rpc_wrapper(config):
    api_type = config['api_type'].upper()
    if api_type == 'EAPI':
        return AristaRPCWrapperEapi
    if api_type == 'JSON':
        return AristaRPCWrapperJSON
    if api_type == 'NOCVX':
        return AristaRPCWrapperNoCvx

    msg = "RPC mechanism %s not recognized" % api_type
    raise AristaConfigError(msg)
