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

from oslo_log import log as logging
import six
import itertools

from networking_arista._i18n import _, _LI
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
                               switch_bindings=None, vlan_type=None,
                               group_info=None):
        LOG.debug("Plugging %s into %s", neutron_port_id, net_id)

        if not self._can_handle_port(segments, switch_bindings, vnic_type):
            LOG.debug("Ignoring port %s", neutron_port_id)
            return

        if group_info is not None:
            # this is a port-channel
            pc = self._get_or_create_port_channel(group_info, switch_bindings)
        else:
            # this is a normal port
            pc = None

        keyfunc = lambda x: x['switch_id']
        data = sorted(switch_bindings, key=keyfunc)
        for switch_id, g in itertools.groupby(data, key=keyfunc):
            server = self._get_server_by_id(switch_id)

            if server is None:
                LOG.warning("Unknown server for port-binding %s", switch_id)
                continue

            vlan_id = segments[-1]['segmentation_id']

            interfaces = []
            port_ids = [b['port_id'] for b in g]
            interfaces.extend(port_ids)

            if pc is None:
                for pc in six.itervalues(
                        self._get_interface_membership(server, port_ids)):
                    if pc:
                        interfaces.append(pc)
            else:
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
                if not vlan_type == 'allowed':
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

    def _get_or_create_port_channel(self, group_info, switch_bindings):
        """
        The following list has to be supported:
            * multiple switches as MLAG with same id
            * multiple interfaces per switch
        """
        # other code checks, if there's a binding, so we better filter empty
        # ones, too
        switch_bindings = [b for b in switch_bindings if b]

        deduplicated_switch_ids = set(binding['switch_id']
                                      for binding in switch_bindings)
        for switch_id in deduplicated_switch_ids:
            server = self._get_server_by_id(switch_id)
            if not server:
                continue

            self._refresh_port_channel_mappings(server)

        # check interface -> port-channel mappings
        port_pcs = set()
        for binding in switch_bindings:
            server = self._get_server_by_id(binding['switch_id'])

            ifm = self._INTERFACE_MEMBERSHIP[server]
            port = binding['port_id']
            if port in ifm:
                port_pcs.add(ifm[port])

        if 0 < len(port_pcs) < len(switch_bindings):
            # there is a port-channel defined on some of our interfaces
            # TODO
            raise NotImplementedError()
        elif len(port_pcs) > 0:
            if len(set(port_pcs)) > 1:
                # there are port-channels defined on all our ports, but they're
                # different
                # TODO
                raise NotImplementedError()

            return port_pcs.pop()
        else:
            # no port-channel -> create one
            return self._create_port_channel(group_info, switch_bindings)

    def _create_port_channel(self, group_info, switch_bindings):
        """ Create new port-channel + add all ports to it.

        This needs to check for free IDs on all switches included in
        `switch_bindings`.
        """
        # find free id > min filling holes
        used_pc_ids = set()
        deduplicated_switch_ids = set(binding['switch_id']
                                      for binding in switch_bindings)
        for switch_id in deduplicated_switch_ids:
            server = self._get_server_by_id(switch_id)

            if server is None:
                LOG.warning("Unknown server for port-binding %s", switch_id)
                continue

            used_pc_ids |= self._USED_PC_IDS[server]

        _MIN_PC_ID = 100
        _MAX_PC_ID = 2000
        new_id = _MIN_PC_ID
        for used_id in sorted(used_pc_ids):
            if new_id < used_id:
                break
            new_id += 1
        if new_id >= _MAX_PC_ID:
            # TODO proper exception
            raise Exception('Too many port-channels on switch.')

        base_cmds = [
            'enable',
            'configure',
            'interface Port-Channel%d' % new_id,
            # TODO more description from group_info?
            """
              {
                  'id': portgroup.uuid,
                  'name': portgroup.name,
                  'bond_mode': portgroup.mode,
                  'bond_properties': {
                      'bond_propertyA': 'valueA',
                      'bond_propertyB': 'valueB',
                  }
              }
            """
            'description -> %s' % group_info['name'],
            'mlag %d' % new_id,
            'exit'
        ]
        keyfunc = lambda x: x['switch_id']
        data = sorted(switch_bindings, key=keyfunc)
        for switch_id, g in itertools.groupby(data, key=keyfunc):
            cmds = list(base_cmds)
            for binding in g:
                port = binding['port_id']
                cmds.extend([
                    'interface %s' % port,
                    'channel-group %d mode passive' % new_id,
                    'exit'
                ])
            cmds.append('exit')

            server = self._get_server_by_id(switch_id)
            if server is None:
                LOG.warning("Unknown server for port-binding %s", switch_id)
                continue

            server(cmds)

        return 'Port-Channel%d' % new_id

    def unplug_port_from_network(self, device_id, device_owner, hostname,
                                 neutron_port_id, network_id, tenant_id, sg,
                                 vnic_type,
                                 switch_bindings=None, segments=None):
        LOG.debug("Plugging out %s of %s", neutron_port_id, network_id)

        if not self._can_handle_port(segments, switch_bindings, vnic_type):
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
            vlan_id = segments[-1]['segmentation_id']

            interfaces = [port_id]
            for pc in six.itervalues(
                    self._get_interface_membership(server, [port_id])):
                if pc:
                    interfaces.append(pc)

            cmds = [
                'enable',
                'configure',
            ]

            for interface in interfaces:
                cmds.extend([
                    'interface %s' % interface,
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
