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

import os
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet

    eventlet.monkey_patch()

from neutron.common import config as common_config

from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from neutron_lib import constants as p_const
from neutron_lib.context import get_admin_context
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_arista._i18n import _, _LI, _LE
from networking_arista.common import constants
from networking_arista.common import db
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc
from networking_arista.common import util
from networking_arista.ml2 import arista_sync
from networking_arista.ml2.rpc.arista_eapi import AristaRPCWrapperEapi
from networking_arista.ml2.rpc import get_rpc_wrapper
from networking_arista.ml2 import sec_group_callback


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('ml2_arista', 'networking_arista.common.config')


def pretty_log(tag, obj):
    # import json
    # log_data = json.dumps(obj, sort_keys=True, indent=4)
    # LOG.debug(tag)
    # LOG.debug(log_data)
    pass


class AristaDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for Arista networking hardware.

    Remembers all networks and VMs that are provisioned on Arista Hardware.
    Does not send network provisioning request if the network has already been
    provisioned before for the given port.
    """

    def __init__(self, rpc=None):
        self.ndb = db_lib.NeutronNets()
        confg = cfg.CONF.ml2_arista
        self.segmentation_type = db_lib.VLAN_SEGMENTATION
        self.timer = loopingcall.FixedIntervalLoopingCall(
            self._synchronization_thread)
        self.sync_timeout = confg['sync_interval']
        if confg.save_config_interval > 0:
            self._config_save_loop = loopingcall.FixedIntervalLoopingCall(
                    self._save_switch_configs_thread)
        self.save_config_interval = confg.save_config_interval
        self.managed_physnets = confg['managed_physnets']

        self.eapi = None

        if rpc:
            LOG.info("Using passed in parameter for RPC")
            self.rpc = rpc
            self.eapi = rpc
        else:
            http_session = util.make_http_session()
            api_type = confg['api_type'].upper()
            self.rpc = get_rpc_wrapper(confg)(self.ndb,
                                              http_session=http_session)
            if api_type == 'NOCVX':
                self.eapi = self.rpc
            else:
                self.eapi = AristaRPCWrapperEapi(self.ndb)
        self.sync_service = arista_sync.SyncService(self.rpc, self.ndb)
        self.rpc.sync_service = self.sync_service
        self.sg_handler = None

    def initialize(self):
        if self.rpc.check_cvx_availability():
            self.rpc.register_with_eos()
            self.rpc.check_supported_features()

        context = get_admin_context()
        self._cleanup_db(context)
        # Registering with EOS updates self.rpc.region_updated_time. Clear it
        # to force an initial sync
        self.rpc.clear_region_updated_time()
        self.sg_handler = sec_group_callback.AristaSecurityGroupHandler(self)
        self.timer.start(self.sync_timeout, stop_on_exception=False)
        self._config_save_loop.start(self.save_config_interval,
                                     stop_on_exception=False)

    def create_network_precommit(self, context):
        """Remember the tenant, and network information."""

        network = context.current
        segments = context.network_segments

        if not self.rpc.hpb_supported():
            # Hierarchical port binding is not supported by CVX, only
            # allow VLAN network type.
            if segments[0][api.NETWORK_TYPE] != p_const.TYPE_VLAN:
                return

        network_id = network['id']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID
        plugin_context = context._plugin_context
        db_lib.remember_tenant(plugin_context, tenant_id)
        for segment in segments:
            db_lib.remember_network_segment(plugin_context,
                                            tenant_id,
                                            network_id,
                                            segment.get('segmentation_id'),
                                            segment.get('id'))

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID
        segments = context.network_segments
        shared_net = network['shared']

        plugin_context = context._plugin_context
        if db_lib.is_network_provisioned(plugin_context, tenant_id,
                                         network_id):
            try:
                network_dict = {
                    'network_id': network_id,
                    'segments': segments,
                    'network_name': network_name,
                    'shared': shared_net}
                self.rpc.create_network(tenant_id, network_dict)
            except arista_exc.AristaRpcError as err:
                LOG.error(_LE("create_network_postcommit: Did not create "
                              "network %(name)s. Reason: %(err)s"),
                          {'name': network_name, 'err': err})
        else:
            LOG.info(_LI('Network %s is not created as it is not found in '
                         'Arista DB'), network_id)

    def update_network_precommit(self, context):
        """At the moment we only support network name change

        Any other change in network is not supported at this time.
        We do not store the network names, therefore, no DB store
        action is performed here.
        """
        new_network = context.current
        orig_network = context.original
        if new_network['name'] != orig_network['name']:
            LOG.info(_LI('Network name changed to %s'), new_network['name'])

    def update_network_postcommit(self, context):
        """At the moment we only support network name change

        If network name is changed, a new network create request is
        sent to the Arista Hardware.
        """
        new_network = context.current
        orig_network = context.original
        plugin_context = context._plugin_context
        if (new_network['name'] != orig_network['name'] or
                new_network['shared'] != orig_network['shared']):
            network_id = new_network['id']
            network_name = new_network['name']
            tenant_id = (new_network['tenant_id'] or
                         constants.INTERNAL_TENANT_ID)
            shared_net = new_network['shared']
            if db_lib.is_network_provisioned(plugin_context,
                                             tenant_id, network_id):
                try:
                    network_dict = {
                        'network_id': network_id,
                        'segments': context.network_segments,
                        'network_name': network_name,
                        'shared': shared_net}
                    self.rpc.create_network(tenant_id, network_dict)
                except arista_exc.AristaRpcError as err:
                    LOG.error(_LE('update_network_postcommit: Did not '
                                  'update network %(name)s. '
                                  'Reason: %(err)s'),
                              {'name': network_name, 'err': err})
            else:
                LOG.info(_LI('Network %s is not updated as it is not found'
                             ' in Arista DB'), network_id)

    def delete_network_precommit(self, context):
        """Delete the network information from the DB."""
        network = context.current
        network_id = network['id']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID
        plugin_context = context._plugin_context
        if db_lib.is_network_provisioned(plugin_context, tenant_id,
                                         network_id):
            if db_lib.are_ports_attached_to_network(plugin_context,
                                                    network_id):
                LOG.info(_LI('Network %s can not be deleted as it '
                             'has ports attached to it'), network_id)
                raise ml2_exc.MechanismDriverError(
                    method='delete_network_precommit')
            else:
                db_lib.forget_network_segment(plugin_context,
                                              tenant_id, network_id)

    def delete_network_postcommit(self, context):
        """Send network delete request to Arista HW."""
        network = context.current
        segments = context.network_segments
        if not self.rpc.hpb_supported():
            # Hierarchical port binding is not supported by CVX, only
            # send the request if network type is VLAN.
            if segments[0][api.NETWORK_TYPE] != p_const.TYPE_VLAN:
                # If network type is not VLAN, do nothing
                return
        network_id = network['id']
        tenant_id = network['tenant_id'] or constants.INTERNAL_TENANT_ID

        # Succeed deleting network in case EOS is not accessible.
        # EOS state will be updated by sync thread once EOS gets
        # alive.
        try:
            self.rpc.delete_network(tenant_id, network_id, segments)
            # if necessary, delete tenant as well.
            self.delete_tenant(context, tenant_id)
        except arista_exc.AristaRpcError as err:
            LOG.error(_LE('delete_network_postcommit: Did not delete '
                          'network %(network_id)s. Reason: %(err)s'),
                      {'network_id': network_id, 'err': err})

    def create_port_precommit(self, context):
        """Remember the information about a VM and its ports

        A VM information, along with the physical host information
        is saved.
        """

        # Returning from here, since the update_port_precommit is performing
        # same operation, and also need of port binding information to decide
        # whether to react to a port create event which is not available when
        # this method is called.

        return

    def _get_physnet_from_link_info(self, port, physnet_info):

        binding_profile = port.get(portbindings.PROFILE)
        if not binding_profile:
            return

        link_info = binding_profile.get('local_link_information')
        if not link_info:
            return

        mac_to_hostname = physnet_info.get('mac_to_hostname', {})
        for link in link_info:
            if link.get('switch_id') in mac_to_hostname:
                physnet = mac_to_hostname.get(link.get('switch_id'))
                return self.rpc.mlag_pairs.get(physnet, physnet)

    def _bind_port_to_baremetal(self, context, segment):

        port = context.current
        vnic_type = port.get('binding:vnic_type')
        if vnic_type != portbindings.VNIC_BAREMETAL:
            # We are only interested in binding baremetal ports.
            return

        binding_profile = port.get(portbindings.PROFILE)
        if not binding_profile:
            return

        link_info = binding_profile.get('local_link_information')
        if not link_info:
            return

        switch_list = []
        for link in link_info:
            switch_list.append(link.get('switch_id'))

        if not switch_list:
            return

        vif_details = {
            portbindings.VIF_DETAILS_VLAN: str(
                segment[api.SEGMENTATION_ID])
        }
        context.set_binding(segment[api.ID],
                            portbindings.VIF_TYPE_OTHER,
                            vif_details,
                            p_const.ACTIVE)
        LOG.debug("AristaDriver: bound port info- port ID %(id)s "
                  "on network %(network)s",
                  {'id': port['id'],
                   'network': context.network.current['id']})

    def bind_port(self, context):
        """Bind port to a network segment.

        Provisioning request to Arista Hardware to plug a host
        into appropriate network is done when the port is created
        this simply tells the ML2 Plugin that we are binding the port
        """
        host_id = context.host
        port = context.current
        physnet_info = {}
        for segment in context.segments_to_bind:
            physnet = segment.get(api.PHYSICAL_NETWORK)
            if not self._is_in_managed_physnets(physnet):
                LOG.debug("bind_port for port %(port)s: physical_network "
                          "%(physnet)s is not managed by Arista "
                          "mechanism driver", {'port': port.get('id'),
                                               'physnet': physnet})
                continue
            # If physnet is not set, we need to look it up using hostname
            # and topology info
            if not physnet:
                if not physnet_info:
                    # We only need to get physnet_info once
                    physnet_info = self.eapi.get_physical_network(host_id)
                if (port.get('binding:vnic_type') ==
                        portbindings.VNIC_BAREMETAL):
                    # Find physnet using link_information in baremetal case
                    physnet = self._get_physnet_from_link_info(port,
                                                               physnet_info)
                else:
                    physnet = physnet_info.get('physnet')
            # If physnet was not found, we cannot bind this port
            if not physnet:
                LOG.debug("bind_port for port %(port)s: no physical_network "
                          "found", {'port': port.get('id')})

                continue

            if segment[api.NETWORK_TYPE] == p_const.TYPE_VXLAN:
                # Check if CVX supports HPB
                if not self.rpc.hpb_supported():
                    LOG.debug("bind_port: HPB is not supported")
                    return

                # The physical network is connected to arista switches,
                # allocate dynamic segmentation id to bind the port to
                # the network that the port belongs to.
                try:
                    next_segment = context.allocate_dynamic_segment(
                        {'id': context.network.current['id'],
                         'network_type': p_const.TYPE_VLAN,
                         'physical_network': physnet})
                except Exception as exc:
                    LOG.error(_LE("bind_port for port %(port)s: Failed to "
                                  "allocate dynamic segment for physnet "
                                  "%(physnet)s. %(exc)s"),
                              {'port': port.get('id'), 'physnet': physnet,
                               'exc': exc})
                    return

                LOG.debug("bind_port for port %(port)s: "
                          "current_segment=%(current_seg)s, "
                          "next_segment=%(next_seg)s",
                          {'port': port.get('id'), 'current_seg': segment,
                           'next_seg': next_segment})
                context.continue_binding(segment['id'], [next_segment])
            elif port.get('binding:vnic_type') == portbindings.VNIC_BAREMETAL:
                # The network_type is vlan, try binding process for baremetal.
                self._bind_port_to_baremetal(context, segment)
            else:
                continue

    def create_port_postcommit(self, context):
        """Plug a physical host into a network.

        Send provisioning request to Arista Hardware to plug a host
        into appropriate network.
        """

        # Returning from here, since the update_port_postcommit is performing
        # same operation, and also need of port binding information to decide
        # whether to react to a port create event which is not available when
        # this method is called.

        return

    def _network_owner_tenant(self, context, network_id, tenant_id):
        tid = tenant_id
        if network_id and tenant_id:
            plugin_context = context._plugin_context
            network_owner = self.ndb.get_network_from_net_id(
                plugin_context,
                network_id
            )
            if network_owner and network_owner[0]['tenant_id'] != tenant_id:
                tid = network_owner[0]['tenant_id'] or tenant_id
        return tid

    def _is_in_managed_physnets(self, physnet):
        if not self.managed_physnets:
            # If managed physnet is empty, accept all.
            return True
        # managed physnet is not empty, find for matching physnet
        return any(pn == physnet for pn in self.managed_physnets)

    def _bound_segments(self, context):
        """Check if a given port is managed by the mechanism driver.

        It returns bound segment dictionary, if physical network in the bound
        segment is included in the managed physical network list.
        """
        if not self.managed_physnets:
            return [binding_level.get(api.BOUND_SEGMENT) for
                    binding_level in context.binding_levels or []]

        bound_segments = []
        for binding_level in (context.binding_levels or []):
            bound_segment = binding_level.get(api.BOUND_SEGMENT)
            if (bound_segment and
                self._is_in_managed_physnets(
                    bound_segment.get(api.PHYSICAL_NETWORK))):
                bound_segments.append(bound_segment)
        return bound_segments

    def _handle_port_migration_precommit(self, context):
        """Handles port migration in precommit

        It updates the port's new host in the DB
        """
        orig_port = context.original
        orig_host = context.original_host
        orig_status = context.original_status
        new_status = context.status
        new_host = context.host
        port_id = orig_port['id']

        if (new_host != orig_host and
                orig_status == n_const.PORT_STATUS_ACTIVE and
                new_status == n_const.PORT_STATUS_DOWN):
            LOG.debug("Handling port migration for: %s " % orig_port)
            network_id = orig_port['network_id']
            tenant_id = orig_port['tenant_id'] or constants.INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context, network_id,
                                                   tenant_id)
            device_id = orig_port['device_id']
            plugin_context = context._plugin_context
            port_provisioned = db_lib.is_port_provisioned(plugin_context,
                                                          port_id,
                                                          orig_host)
            if port_provisioned:
                db_lib.update_port(plugin_context,
                                   device_id, new_host, port_id,
                                   network_id, tenant_id)

            return True

    def _handle_port_migration_postcommit(self, context):
        """Handles port migration in postcommit

        In case of port migration, it removes the port from the original host
        and also it release the segment id if no port is attached to the same
        segment id that the port is attached to.
        """
        orig_port = context.original
        orig_host = context.original_host
        orig_status = context.original_status
        new_status = context.status
        new_host = context.host

        if (new_host != orig_host and
                orig_status == n_const.PORT_STATUS_ACTIVE and
                new_status == n_const.PORT_STATUS_DOWN):

            self._try_to_release_dynamic_segment(context, migration=True)

            # Handling migration case.
            # 1. The port should be unplugged from network
            # 2. If segment_id is provisioned and it not bound to any port it
            # should be removed from EOS.
            network_id = orig_port['network_id']
            tenant_id = orig_port['tenant_id'] or constants.INTERNAL_TENANT_ID
            # Ensure that we use tenant Id for the network owner
            tenant_id = self._network_owner_tenant(context, network_id,
                                                   tenant_id)
            for binding_level in context._original_binding_levels:
                if self._network_provisioned(
                        context, tenant_id, network_id,
                        segment_id=binding_level.segment_id):
                    # Removing the port form original host
                    self._delete_port(context, orig_port, orig_host, tenant_id,
                                      segments=[binding_level])

                    # If segment id is not bound to any port, then
                    # remove it from EOS
                    plugin_context = context._plugin_context
                    segment = self.ndb.get_segment_by_id(
                        plugin_context,
                        binding_level.segment_id)
                    if not segment:
                        try:
                            segment_info = [{
                                'id': binding_level.segment_id,
                                'network_id': network_id,
                            }]
                            LOG.debug("migration_postcommit:"
                                      "deleting segment %s", segment_info)
                            self.rpc.delete_network_segments(tenant_id,
                                                             segment_info)
                            # Remove the segment from the provisioned
                            # network DB.
                            db_lib.forget_network_segment(
                                plugin_context, tenant_id, network_id,
                                binding_level.segment_id)
                        except arista_exc.AristaRpcError:
                            LOG.info(constants.EOS_UNREACHABLE_MSG)

            return True

    def update_port_precommit(self, context):
        """Update the name of a given port.

        At the moment we only support port name change.
        Any other change to port is not supported at this time.
        We do not store the port names, therefore, no DB store
        action is performed here.
        """
        new_port = context.current
        orig_port = context.original
        if new_port['name'] != orig_port['name']:
            LOG.info(_LI('Port name changed to %s'), new_port['name'])
        device_id = new_port['device_id']
        host = context.host

        pretty_log("update_port_precommit: new", new_port)
        pretty_log("update_port_precommit: orig", orig_port)

        if new_port['device_owner'] == 'compute:probe':
            return

        # Check if the port is part of managed physical network
        seg_info = self._bound_segments(context)
        if not seg_info:
            # Ignoring the update as the port is not managed by
            # arista mechanism driver.
            return

        # Check if it is port migration case
        if self._handle_port_migration_precommit(context):
            return

        # device_id and device_owner are set on VM boot
        port_id = new_port['id']
        network_id = new_port['network_id']
        tenant_id = new_port['tenant_id'] or constants.INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)

        plugin_context = context._plugin_context
        for seg in seg_info:
            if not self._network_provisioned(context, tenant_id, network_id,
                                             seg[api.SEGMENTATION_ID],
                                             seg[api.ID]):
                LOG.info(
                    _LI("Adding %s to provisioned network database"), seg)
                db_lib.remember_tenant(plugin_context, tenant_id)
                db_lib.remember_network_segment(
                    plugin_context, tenant_id, network_id,
                    seg[api.SEGMENTATION_ID], seg[api.ID])

        port_down = False
        if (new_port['device_owner'] ==
                n_const.DEVICE_OWNER_DVR_INTERFACE):
            # We care about port status only for DVR ports because
            # for DVR, a single port exists on multiple hosts. If a port
            # is no longer needed on a host then the driver gets a
            # port_update notification for that <port, host> with the
            # port status as PORT_STATUS_DOWN.
            port_down = context.status == n_const.PORT_STATUS_DOWN

        if host and not port_down:
            port_host_filter = None
            if (new_port['device_owner'] ==
                    n_const.DEVICE_OWNER_DVR_INTERFACE):
                # <port, host> uniquely identifies a DVR port. Other
                # ports are identified by just the port id
                port_host_filter = host

            port_provisioned = db_lib.is_port_provisioned(
                plugin_context,
                port_id, port_host_filter)

            if not port_provisioned:
                LOG.info("Remembering the port")
                # Create a new port in the DB
                db_lib.remember_tenant(plugin_context, tenant_id)
                db_lib.remember_vm(plugin_context,
                                   device_id, host, port_id,
                                   network_id, tenant_id)
            else:
                if (new_port['device_id'] != orig_port['device_id'] or
                        context.host != context.original_host or
                        new_port['network_id'] != orig_port['network_id'] or
                        new_port['tenant_id'] != orig_port['tenant_id']):
                    LOG.info("Updating the port")
                    # Port exists in the DB. Update it
                    db_lib.update_port(plugin_context, device_id, host,
                                       port_id,
                                       network_id, tenant_id)
        else:  # Unbound or down port does not concern us
            orig_host = context.original_host
            LOG.info("Forgetting the port on %s" % str(orig_host))
            db_lib.forget_port(plugin_context, port_id, orig_host)

    def _port_updated(self, context):
        """Returns true if any port parameters have changed."""
        new_port = context.current
        orig_port = context.original
        return (new_port['device_id'] != orig_port['device_id'] or
                context.host != context.original_host or
                new_port['network_id'] != orig_port['network_id'] or
                new_port['tenant_id'] != orig_port['tenant_id'])

    def update_port_postcommit(self, context):
        """Update the name of a given port in EOS.

        At the moment we only support port name change
        Any other change to port is not supported at this time.
        """
        port = context.current
        orig_port = context.original

        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host
        is_vm_boot = device_id and device_owner

        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        bindings = []
        vlan_type = 'native' if vnic_type == 'baremetal' else 'allowed'
        if binding_profile:
            bindings = binding_profile.get('local_link_information', bindings)
            vlan_type = binding_profile.get('vlan_type', vlan_type)

        port_id = port['id']
        port_name = port['name']
        network_id = port['network_id']
        tenant_id = port['tenant_id'] or constants.INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)
        sg = port['security_groups']
        orig_sg = orig_port['security_groups']

        pretty_log("update_port_postcommit: new", port)
        pretty_log("update_port_postcommit: orig", orig_port)

        seg_info = self._bound_segments(context)
        if not seg_info:
            LOG.debug("Ignoring the update as the port %s is not managed by "
                      "Arista switches.", port_id)
            return

        # Check if it is port migration case
        if self._handle_port_migration_postcommit(context):
            # Return from here as port migration is already handled.
            return

        hostname = self._host_name(host)
        port_host_filter = None
        if port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE:
            # <port, host> uniquely identifies a DVR port. Other
            # ports are identified by just the port id
            port_host_filter = host
        plugin_context = context._plugin_context
        port_provisioned = db_lib.is_port_provisioned(plugin_context, port_id,
                                                      port_host_filter)
        # If network does not exist under this tenant,
        # it may be a shared network. Get shared network owner Id
        net_provisioned = self._network_provisioned(context,
                                                    tenant_id, network_id)
        for seg in seg_info:
            if not self._network_provisioned(context, tenant_id, network_id,
                                             segmentation_id=seg[
                                                 api.SEGMENTATION_ID]):
                net_provisioned = False
                break
        segments = []
        if net_provisioned:
            if self.rpc.hpb_supported():
                segments = seg_info
                all_segments = self.ndb.get_all_network_segments(
                    plugin_context, network_id)
                try:
                    self.rpc.create_network_segments(
                        tenant_id, network_id,
                        context.network.current['name'], all_segments)
                except arista_exc.AristaRpcError:
                    LOG.error(_LE("Failed to create network segments"))
                    raise ml2_exc.MechanismDriverError()
            else:
                # For non HPB cases, the port is bound to the static
                # segment
                segments = self.ndb.get_network_segments(plugin_context,
                                                         network_id)

        try:
            orig_host = context.original_host
            port_down = False
            if port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE:
                # We care about port status only for DVR ports
                port_down = context.status == n_const.PORT_STATUS_DOWN

            if orig_host and (port_down or host != orig_host):
                try:
                    LOG.info("Deleting the port %s" % str(orig_port))
                    # The port moved to a different host or the VM
                    # connected to the port was deleted or its in DOWN
                    # state. So delete the old port on the old host.
                    self._delete_port(context, orig_port, orig_host, tenant_id,
                                      segments=segments)
                except ml2_exc.MechanismDriverError:
                    # If deleting a port fails, then not much can be done
                    # about it. Log a warning and move on.
                    LOG.warning(constants.UNABLE_TO_DELETE_PORT_MSG)
            if port_provisioned and net_provisioned and hostname and \
                is_vm_boot and not port_down:
                LOG.info(_LI("Port plugged into network"))
                # Plug port into the network only if it exists in the db
                # and is bound to a host and the port is up.
                self.rpc.plug_port_into_network(device_id,
                                                hostname,
                                                port_id,
                                                network_id,
                                                tenant_id,
                                                port_name,
                                                device_owner,
                                                sg, orig_sg,
                                                vnic_type,
                                                segments=segments,
                                                switch_bindings=bindings,
                                                vlan_type=vlan_type)
            else:
                LOG.info(_LI("Port not plugged into network"))
        except arista_exc.AristaRpcError as err:
            LOG.error(_LE('update_port_postcommit: Did not update '
                          'port %(port_id)s. Reason: %(err)s'),
                      {'port_id': port_id, 'err': err})

    def delete_port_precommit(self, context):
        """Delete information about a VM and host from the DB."""
        # Check if the port is part of managed physical network
        seg_info = self._bound_segments(context)
        if not seg_info:
            # Ignoring the update as the port is not managed by
            # arista mechanism driver.
            return

        port = context.current
        pretty_log("delete_port_precommit:", port)

        port_id = port['id']
        host_id = context.host
        if host_id:
            plugin_context = context._plugin_context
            db_lib.forget_port(plugin_context, port_id, host_id)

    def delete_port_postcommit(self, context):
        """Unplug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        # Check if the port is part of managed physical network
        seg_info = self._bound_segments(context)
        if not seg_info:
            # Ignoring the update as the port is not managed by
            # arista mechanism driver.
            return

        port = context.current
        host = context.host
        network_id = port['network_id']

        tenant_id = port['tenant_id'] or constants.INTERNAL_TENANT_ID
        # Ensure that we use tenant Id for the network owner
        tenant_id = self._network_owner_tenant(context, network_id, tenant_id)

        pretty_log("delete_port_postcommit:", port)

        # If this port is the last one using dynamic segmentation id,
        # and the segmentation id was allocated by this driver, it needs
        # to be released.
        self._try_to_release_dynamic_segment(context)

        try:
            self._delete_port(context, port, host, tenant_id,
                              segments=seg_info)
            self._delete_segment(context, tenant_id)
        except ml2_exc.MechanismDriverError:
            # Can't do much if deleting a port failed.
            # Log a warning and continue.
            LOG.warning(constants.UNABLE_TO_DELETE_PORT_MSG)

    def _delete_port(self, context, port, host, tenant_id, segments=None):
        """Deletes the port from EOS.

        param port: Port which is to be deleted
        param host: The host on which the port existed
        param tenant_id: The tenant to which the port belongs to. Some times
                         the tenant id in the port dict is not present (as in
                         the case of HA router).
        """
        device_id = port['device_id']
        port_id = port['id']
        network_id = port['network_id']
        device_owner = port['device_owner']
        vnic_type = port['binding:vnic_type']
        binding_profile = port['binding:profile']
        switch_bindings = []
        if binding_profile:
            switch_bindings = binding_profile.get('local_link_information', [])
        sg = port['security_groups']

        if not device_id or not host:
            LOG.warning(constants.UNABLE_TO_DELETE_DEVICE_MSG)
            return

        # sometimes segments are snapshot objects, let's resolve that here
        if segments:
            plugin_context = context._plugin_context
            for n, segment in enumerate(segments):
                if not isinstance(segment, dict) and \
                        not hasattr(segment, 'segmentation_id') and \
                        hasattr(segment, 'segment_id'):
                    segments[n] = db_lib.get_segmentation_id_by_segment_id(
                                        plugin_context,
                                        segment.segment_id
                    )

        try:
            device_ports = db_lib.get_bm_ports_for_device(
                context._plugin_context, device_id)
            port_net_in_use = False
            for device_port in device_ports:
                if device_port.id != port_id and \
                        device_port.network_id == network_id:
                    LOG.warning("Will not deprovision network %s on port %s "
                                "as port %s is still on this network",
                                network_id, port_id, device_port.id)
                    port_net_in_use = True
            if not cfg.CONF.ml2_arista.skip_unplug and not port_net_in_use:
                hostname = self._host_name(host)
                self.rpc.unplug_port_from_network(
                    device_id, device_owner, hostname, port_id, network_id,
                    tenant_id, sg, vnic_type, switch_bindings=switch_bindings,
                    segments=segments)
                if not cfg.CONF.ml2_arista.sec_group_background_only:
                    self.rpc.remove_security_group(sg, switch_bindings)

            # if necessary, delete tenant as well.
            self.delete_tenant(context, tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(constants.EOS_UNREACHABLE_MSG)

    def _delete_segment(self, context, tenant_id):
        """Deletes a dynamic network segment from EOS.

        param context: The port context
        param tenant_id: The tenant which the port belongs to
        """

        if not self.rpc.hpb_supported():
            # Returning as HPB not supported by CVX
            return

        port = context.current
        network_id = port.get('network_id')

        if not context._binding_levels:
            return

        plugin_context = context._plugin_context
        for binding_level in context._binding_levels:
            LOG.debug("deleting segment %s", binding_level.segment_id)
            if self._network_provisioned(context, tenant_id, network_id,
                                         segment_id=binding_level.segment_id):
                segment = self.ndb.get_segment_by_id(
                    plugin_context, binding_level.segment_id)
                if not segment:
                    # The segment is already released. Delete it from EOS
                    LOG.debug("Deleting segment %s", binding_level.segment_id)
                    try:
                        segment_info = {
                            'id': binding_level.segment_id,
                            'network_id': network_id,
                        }
                        self.rpc.delete_network_segments(tenant_id,
                                                         [segment_info])
                        # Remove the segment from the provisioned network DB.
                        db_lib.forget_network_segment(plugin_context,
                                                      tenant_id, network_id,
                                                      binding_level.segment_id)
                    except arista_exc.AristaRpcError:
                        LOG.info(constants.EOS_UNREACHABLE_MSG)
                else:
                    LOG.debug("Cannot delete segment_id %(segid)s "
                              "segment is %(seg)s",
                              {'segid': binding_level.segment_id,
                               'seg': segment})

    def _try_to_release_dynamic_segment(self, context, migration=False):
        """Release dynamic segment allocated by the driver

        If this port is the last port using the segmentation id allocated
        by the driver, it should be released
        """
        if migration:
            host = context.original_host
        else:
            host = context.host

        physnet_info = self.eapi.get_physical_network(host, context=context)
        physnet = physnet_info.get('physnet')
        if not physnet:
            return

        binding_levels = context.binding_levels
        LOG.debug("_try_release_dynamic_segment: "
                  "binding_levels=%(bl)s", {'bl': binding_levels})
        if not binding_levels:
            return

        segment_id = None
        bound_drivers = []
        for binding_level in binding_levels:
            bound_segment = binding_level.get(api.BOUND_SEGMENT)
            driver = binding_level.get(api.BOUND_DRIVER)
            bound_drivers.append(driver)
            if (bound_segment and
                    bound_segment.get('physical_network') == physnet and
                    bound_segment.get('network_type') == p_const.TYPE_VLAN):
                segment_id = bound_segment.get('id')
                break

        plugin_context = context._plugin_context

        # If the segment id is found and it is bound by this driver, and also
        # the segment id is not bound to any other port, release the segment.
        # When Arista driver participate in port binding by allocating dynamic
        # segment and then calling continue_binding, the driver should the
        # second last driver in the bound drivers list.
        if (segment_id and bound_drivers[-2:-1] ==
                [constants.MECHANISM_DRV_NAME]):
            filters = {'segment_id': segment_id}
            result = db_lib.get_port_binding_level(plugin_context, filters)
            LOG.debug("Looking for entry with filters=%(filters)s "
                      "result=%(result)s ", {'filters': filters,
                                             'result': result})
            if not result:
                # The requested segment_id does not exist in the port binding
                # database. Release the dynamic segment.
                context.release_dynamic_segment(segment_id)
                LOG.debug("Released dynamic segment %(seg)s allocated "
                          "by %(drv)s", {'seg': segment_id,
                                         'drv': bound_drivers[-2]})

    def delete_tenant(self, context, tenant_id):
        """delete a tenant from DB.

        A tenant is deleted only if there is no network or VM configured
        configured for this tenant.
        """
        plugin_context = context._plugin_context
        objects_for_tenant = (
            db_lib.num_nets_provisioned(plugin_context, tenant_id) +
            db_lib.num_vms_provisioned(plugin_context, tenant_id)
        )
        if not objects_for_tenant:
            db_lib.forget_tenant(plugin_context, tenant_id)
            try:
                self.rpc.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError:
                LOG.info(constants.EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError(method='delete_tenant')

    def _host_name(self, hostname):
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        return hostname if fqdns_used else hostname.split('.')[0]

    def _save_switch_configs_thread(self):
        self.sync_service.save_switch_configs()

    def _synchronization_thread(self):
        self.sync_service.do_synchronize()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.stop()
            self.timer = None

    # @enginefacade.writer
    def _cleanup_db(self, context):
        """Clean up any unnecessary entries in our DB."""
        session = context.session
        with session.begin(subtransactions=True):
            arista_vms = db.AristaProvisionedVms
            arista_nets = db.AristaProvisionedNets

            missing_nets = \
                session.query(arista_nets.network_id). \
                outerjoin(models_v2.Network,
                          models_v2.Network.id == arista_nets.network_id
                          ).filter(
                    models_v2.Network.id.is_(None)
                ).subquery()

            session.query(arista_vms). \
                filter(arista_vms.network_id.in_(missing_nets)).delete(False)
            session.query(arista_nets). \
                filter(arista_nets.network_id.in_(missing_nets)).delete(False)

    def _network_provisioned(self, context, tenant_id, network_id,
                             segmentation_id=None, segment_id=None):
        # If network does not exist under this tenant,
        # it may be a shared network.
        plugin_context = context._plugin_context
        return db_lib.is_network_provisioned(
            plugin_context, tenant_id, network_id, segmentation_id,
            segment_id) or \
            self.ndb.get_shared_network_owner_id(plugin_context, network_id)

    def create_security_group(self, context, sg):
        pass

    def delete_security_group(self, context, sg):
        pass

    def update_security_group(self, context, sg):
        if (cfg.CONF.ml2_arista.sec_group_background_only or
                not self._is_security_group_used(context, sg['id'])):
            return

        try:
            self.rpc.create_acl(context, sg)
        except Exception:
            msg = (_('Failed to create ACL on EOS %s') % sg)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def create_security_group_rule(self, context, sgr):
        if (cfg.CONF.ml2_arista.sec_group_background_only or
                not self._is_security_group_used(context,
                                                 sgr['security_group_id'])):
            return

        try:
            self.rpc.create_acl_rule(context, sgr)
        except Exception:
            msg = (_('Failed to create ACL rule on EOS %s') % sgr)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    def delete_security_group_rule(self, context, sgr_id):
        if cfg.CONF.ml2_arista.sec_group_background_only:
            return
        if not sgr_id:
            return
        sgr = self.ndb.get_security_group_rule(context, sgr_id)
        if not sgr:
            return

        if not self._is_security_group_used(context, sgr['security_group_id']):
            return

        try:
            self.rpc.delete_acl_rule(sgr)
        except Exception:
            msg = (_('Failed to delete ACL rule on EOS %s') % sgr)
            LOG.exception(msg)
            raise arista_exc.AristaSecurityGroupError(msg=msg)

    @staticmethod
    def _is_security_group_used(context, security_group_id):
        sg_id = sg_db.SecurityGroupPortBinding.security_group_id
        port_id = sg_db.SecurityGroupPortBinding.port_id

        result = context.session.query(sg_id).filter(
            sg_id == security_group_id).join(
            db.AristaProvisionedVms, db.AristaProvisionedVms.port_id == port_id
        ).first()
        return result is not None


def cli():
    import json
    import six
    import sys

    from collections import defaultdict
    from neutron.db.models_v2 import Port
    from neutron.plugins.ml2.models import NetworkSegment
    from neutron.plugins.ml2.models import PortBindingLevel
    from oslo_config import cfg
    from sqlalchemy.orm import contains_eager, joinedload, relationship

    cfg.CONF.register_cli_opts([
        cfg.MultiStrOpt('port_id',
                        short='p',
                        default=[],
                        help=''),
        cfg.BoolOpt('all_ports',
                    default=False,
                    help='Should we sync all ports'),

    ])
    common_config.init(sys.argv[1:])

    if not cfg.CONF.all_ports and not cfg.CONF.port_id:
        LOG.error("Nothing to do, specify either port_id or all_ports")
        return

    context = get_admin_context()
    ndb = db_lib.NeutronNets()
    confg = cfg.CONF.ml2_arista
    confg.http_pool_block = True

    rpc = get_rpc_wrapper(confg)(ndb)

    Port.port_binding_levels = relationship(PortBindingLevel)
    PortBindingLevel.segment = relationship(NetworkSegment,
                                            lazy='subquery')

    items = defaultdict(list)
    with context.session.begin():
        session = context.session
        ports = session.query(Port). \
            join(Port.port_binding). \
            join(Port.port_binding_levels). \
            options(joinedload(Port.security_groups)). \
            filter(PortBindingLevel.driver == constants.MECHANISM_DRV_NAME). \
            options(contains_eager(Port.port_binding_levels))

        if cfg.CONF.port_id:
            ports = ports.filter(Port.id.in_(cfg.CONF.port_id))

        for port in ports:
            port_id = port.id
            device_id = port.device_id
            network_id = port.network_id
            port_name = port.name
            device_owner = port.device_owner
            binding = port.port_binding
            hostname = binding.host
            vnic_type = binding.vnic_type
            orig_sg = None
            tenant_id = port.tenant_id
            sg = [sg.security_group_id for sg in port.security_groups]
            binding_profile = json.loads(binding.profile)
            bindings = binding_profile.get('local_link_information', [])
            vlan_type = binding_profile.get('vlan_type', 'native')
            segments = [{'id': level.segment_id, 'level': level.level,
                         'physical_network': level.segment.physical_network,
                         'segmentation_id': level.segment.segmentation_id,
                         'network_type': level.segment.network_type,
                         'is_dynamic': level.segment.is_dynamic,
                         }
                        for level in port.port_binding_levels
                        if level.driver == 'arista'
                        ]

            items[device_id].append((hostname, port_id, network_id, tenant_id,
                          port_name, device_owner, sg, orig_sg, vnic_type,
                          segments, bindings, vlan_type))

    from eventlet.greenpool import GreenPool as Pool

    def plug(device_ports):
        device_id, ports = device_ports

        # Plug the ports, first the native, then allowed
        for hostname, port_id, network_id, tenant_id, \
                port_name, device_owner, sg, orig_sg, vnic_type, \
                segments, bindings, vlan_type in \
                sorted(ports, key=lambda x: x[-1] == 'allowed'):

            print('Node: {}: Port {} {}'
                  .format(device_id, port_id, vlan_type))
            rpc.plug_port_into_network(
                device_id, hostname, port_id, network_id, tenant_id, port_name,
                device_owner, sg, orig_sg, vnic_type,
                segments=segments,
                switch_bindings=bindings,
                vlan_type=vlan_type)

    p = Pool(8)
    for item in p.imap(plug, six.iteritems(items)):
        pass
