# Copyright (c) 2018 SAP SE
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
from collections import defaultdict

from oslo_log import log as logging
import six

from networking_arista._i18n import _, _LI
from networking_arista.common.util import get_attr_or_item
from networking_arista.ml2 import arista_sec_gp
from networking_arista.ml2.rpc.base import AristaRPCWrapperBase

LOG = logging.getLogger(__name__)


class AristaRPCWrapperNoCvx(AristaRPCWrapperBase,
                            arista_sec_gp.AristaSwitchRPCMixin):
    """Wraps Arista Direct Communication.
    """

    def __init__(self, neutron_db=None, http_session=None):
        super(AristaRPCWrapperNoCvx, self).__init__(neutron_db,
                                                    http_session=http_session)
        arista_sec_gp.AristaSwitchRPCMixin._validate_config(
            self, _('when "api_type" is "nocvx"')
        )

    # This is the only EAPI call, which we hopefully never need
    def get_physical_network(self, host_id, context=None):
        physnet = None
        if context and context.bottom_bound_segment:
            physnet = context.bottom_bound_segment['physical_network']
        return {'physnet': physnet}

    def check_cvx_availability(self):
        return True

    def plug_port_into_network(self, device_id, host_id, neutron_port_id,
                               net_id, tenant_id, port_name, device_owner,
                               sg, orig_sg, vnic_type, segments=None,
                               switch_bindings=None, vlan_type=None):
        LOG.debug("Plugging %s into %s", neutron_port_id, net_id)

        if not self._can_handle_port(segments, switch_bindings, vnic_type):
            LOG.debug("Ignoring port %s", neutron_port_id)
            return

        for binding in switch_bindings:
            if not binding:
                continue

            server = self._get_server(switch_info=binding['switch_info'],
                                      switch_id=binding['switch_id'])
            if server is None:
                LOG.warning("Unknown server for port-binding %s", binding)
                continue

            port_id = binding['port_id']
            vlan_id = get_attr_or_item(segments[-1], 'segmentation_id')

            interfaces = [port_id]

            for pc in six.itervalues(
                    self._get_interface_membership(server, [port_id])):
                if pc:
                    interfaces.append(pc)

            # Setup VLAN
            cmds = [
                'enable',
                'configure',
                'vlan %d' % vlan_id,
                'name %s' % net_id,
                'state active',
                'exit'
            ]
            # Setup interface with the named VLAN
            for interface in interfaces:
                if vlan_type != 'allowed':
                    cmds.extend([
                        'interface %s' % interface,
                        'switchport mode trunk',
                        'switchport trunk allowed vlan add %d' % vlan_id,
                        'switchport trunk native vlan %d' % vlan_id,
                        'exit',
                    ])
                else:
                    cmds.extend([
                        'interface %s' % interface,
                        'switchport mode trunk',
                        'switchport trunk allowed vlan add %d' % vlan_id,
                        'exit',
                    ])

            cmds.append('exit')
            server(cmds)

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 neutron_port_id, network_id, tenant_id, sg,
                                 vnic_type,
                                 switch_bindings=None, segments=None):
        LOG.debug("Plugging out %s of %s", neutron_port_id, network_id)

        if not self._can_handle_port(segments, switch_bindings, vnic_type):
            return

        if len(segments) == 0 or segments[-1] is None:
            LOG.warning("No segments found on unplug event for port %s on net "
                        "%s with bindings %s, segments were %s",
                        neutron_port_id, network_id, switch_bindings, segments)
            return

        # get all information out of the port
        vlan_id = get_attr_or_item(segments[-1], 'segmentation_id')
        iface_dict = defaultdict(set)
        for binding in switch_bindings:
            if not binding:
                continue

            server = self._get_server(switch_info=binding['switch_info'],
                                      switch_id=binding['switch_id'])
            if server is None:
                LOG.warning("Unknown server for port-binding %s", binding)
                continue

            switchport = binding['port_id']
            iface_dict[server].add(switchport)

        # find all members of all portchannels we might have to change
        for server in list(iface_dict):
            for iface in list(iface_dict[server]):
                if iface.startswith("Port-Channel"):
                    continue
                ifs = self._get_mlag_pc_members_from_iface(server, iface)
                for _server, _if in ifs:
                    iface_dict[_server].add(_if)

        LOG.debug("Unplug network event for port %s, dict is %s",
                  neutron_port_id, iface_dict)
        for server, ifaces in iface_dict.items():
            cmds = [
                'enable',
                'configure',
            ]

            for iface in ifaces:
                cmds.extend([
                    'interface %s' % iface,
                    'switchport trunk allowed vlan remove %d' % vlan_id,
                    'exit',
                ])
            cmds.append('exit')

            server(cmds)

    @staticmethod
    def _can_handle_port(segments, switch_bindings, vnic_type):
        if vnic_type != 'baremetal':
            LOG.info(_LI("Unsupported vnic_type %s"), vnic_type)
            return False
        if not switch_bindings:
            LOG.info('No switch bindings')
            return False
        if not segments:
            LOG.info('No segments')
            return False
        return True

    def save_switch_configs(self):
        self._maintain_connections()

        success_count = 0
        for switch_ip, server in self._SERVER_BY_IP.items():
            try:
                result = server(["copy running-config startup-config"])[0]
                msg = "\n".join(result.get('messages', []))

                if 'Copy completed successfully' in msg:
                    success_count += 1
                else:
                    LOG.error("Could not save config in switch, "
                              "switch returned unexpected result: %s",
                              result)
            except Exception as e:
                LOG.error("Could not save config on switch %s: %s - %s",
                          switch_ip, type(e), str(e))

        LOG.info("Successfully saved %s switch configs", success_count)

    def bm_and_dvr_supported(self):
        return True

    def hpb_supported(self):
        return True

    def register_with_eos(self, sync=False):
        return True

    def check_supported_features(self):
        return True

    def get_region_updated_time(self):
        return {'regionTimestamp': None}

    def delete_this_region(self):
        pass

    def sync_start(self):
        return False  # We do not sync

    def sync_end(self):
        return True

    def get_tenants(self):
        return {}

    def delete_tenant_bulk(self, tenant_list, sync=False):
        return

    def create_network_bulk(self, tenant_id, network_list, sync=False):
        pass

    def create_network_segments(self, tenant_id, network_id,
                                network_name, segments):
        pass

    def delete_network_bulk(self, tenant_id, network_id_list, sync=False):
        pass

    def delete_network_segments(self, tenant_id, network_segments):
        pass

    def create_instance_bulk(self, tenant_id, neutron_ports, vms,
                             port_profiles, sync=False):
        pass

    def delete_instance_bulk(self, tenant_id, instance_id_list, instance_type,
                             sync=False):
        pass

    def delete_vm_bulk(self, tenant_id, vm_id_list, sync=False):
        pass
