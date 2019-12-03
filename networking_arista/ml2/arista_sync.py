# Copyright (c) 2014 OpenStack Foundation
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
import six

from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import log as logging
from tooz import coordination

from networking_arista._i18n import _
from networking_arista.common import constants
from networking_arista.common import db_lib
from networking_arista.common import exceptions as arista_exc

LOG = logging.getLogger(__name__)

# EAPI error messages of interest
BAREMETAL_NOT_SUPPORTED = 'EOS version on CVX does not support Baremetal'


class SyncService(object):
    """Synchronization of information between Neutron and EOS

    Periodically (through configuration option), this service
    ensures that Networks and VMs configured on EOS/Arista HW
    are always in sync with Neutron DB.
    """

    def __init__(self, rpc_wrapper, neutron_db):
        self._context = neutron_context.get_admin_context()
        self._rpc = rpc_wrapper
        self._ndb = neutron_db
        self._force_sync = True
        self._region_updated_time = None
        self._coordinator = None
        self._member_id = None
        self._setup_coordination()

    def _setup_coordination(self):
        if not cfg.CONF.ml2_arista.coordinator_url:
            return

        self._member_id = six.binary_type(
            "{}({})".format(cfg.CONF.host, os.getpid()).encode('ascii'))

        coordinator = coordination.get_coordinator(
            cfg.CONF.ml2_arista.coordinator_url,
            self._member_id,
            [coordination.Characteristics.DISTRIBUTED_ACROSS_HOSTS],
            membership_timeout=cfg.CONF.ml2_arista.sync_interval * 2,
            leader_timeout=cfg.CONF.ml2_arista.sync_interval * 2,
            lock_timeout=cfg.CONF.ml2_arista.sync_interval * 2,
        )
        self._coordinator = coordinator

        coordinator.start()

        self._group_id = six.binary_type(
            six.text_type('ml2_arista_sync_service').encode('ascii'))

        try:
            request = coordinator.create_group(self._group_id)
            request.get()
        except coordination.GroupAlreadyExist:
            pass

        request = coordinator.join_group(self._group_id)
        request.get()

        coordinator.watch_elected_as_leader(
            self._group_id, self._become_leader)

    def _become_leader(self, event):
        if event.member_id == self._member_id:
            LOG.info("I am the new leader!")

    def force_sync(self):
        """Sets the force_sync flag."""
        self._force_sync = True

    def _check_leader(self):
        if not self._coordinator:
            return True

        self._coordinator.heartbeat()
        self._coordinator.run_watchers()
        current_leader = self._coordinator.get_leader(self._group_id).get()
        return current_leader == self._member_id

    def save_switch_configs(self):
        """Let each switch write its running-config to its startup-config"""
        if not self._check_leader():
            LOG.info("Not leader, not saving config")
            return

        try:
            self._rpc.save_switch_configs()
        except Exception as e:
            LOG.exception(e)

    def do_synchronize(self):
        """Periodically check whether EOS is in sync with ML2 driver.

           If ML2 database is not in sync with EOS, then compute the diff and
           send it down to EOS.
        """

        if not self._check_leader():
            LOG.info("Not leader")
            return

        # Perform sync of Security Groups unconditionally
        try:
            self._rpc.perform_sync_of_sg(self._context)
        except Exception as e:
            LOG.exception(e)

        # Check whether CVX is available before starting the sync.
        if not self._rpc.check_cvx_availability():
            LOG.warning("Not syncing as CVX is unreachable")
            self.force_sync()
            return

        if not self._sync_required():
            return

        LOG.info('Attempting to sync')
        # Send 'sync start' marker.
        if not self._rpc.sync_start():
            LOG.info(_('Not starting sync, setting force'))
            self._force_sync = True
            return

        # Perform the actual synchronization.
        self.synchronize(self._context)

        # Send 'sync end' marker.
        if not self._rpc.sync_end():
            LOG.info(_('Sync end failed, setting force'))
            self._force_sync = True
            return

        self._set_region_updated_time()

    # @enginefacade.reader
    def synchronize(self, context):
        """Sends data to EOS which differs from neutron DB."""

        LOG.info(_('Syncing Neutron <-> EOS'))
        try:
            # Register with EOS to ensure that it has correct credentials
            self._rpc.register_with_eos(sync=True)
            self._rpc.check_supported_features()
            eos_tenants = self._rpc.get_tenants()
        except arista_exc.AristaRpcError:
            LOG.warning(constants.EOS_UNREACHABLE_MSG)
            self._force_sync = True
            return

        db_tenants = db_lib.get_tenants(context)

        # Delete tenants that are in EOS, but not in the database
        tenants_to_delete = frozenset(eos_tenants.keys()).difference(
            db_tenants.keys())

        if tenants_to_delete:
            try:
                self._rpc.delete_tenant_bulk(tenants_to_delete, sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True
                return

        # None of the commands have failed till now. But if subsequent
        # operations fail, then force_sync is set to true
        self._force_sync = False

        # Create a dict of networks keyed by id.
        neutron_nets = dict(
            (network['id'], network) for network in
            self._ndb.get_all_networks(context)
        )

        # Get Baremetal port switch_bindings, if any
        port_profiles = db_lib.get_all_portbindings(context)
        # To support shared networks, split the sync loop in two parts:
        # In first loop, delete unwanted VM and networks and update networks
        # In second loop, update VMs. This is done to ensure that networks for
        # all tenats are updated before VMs are updated
        instances_to_update = {}
        for tenant in db_tenants.keys():
            db_nets = db_lib.get_networks(context, tenant)
            db_instances = db_lib.get_vms(context, tenant)

            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms, eos_bms, eos_routers = self._get_eos_vms(eos_tenants,
                                                              tenant)

            db_nets_key_set = frozenset(db_nets.keys())
            db_instances_key_set = frozenset(db_instances.keys())
            eos_nets_key_set = frozenset(eos_nets.keys())
            eos_vms_key_set = frozenset(eos_vms.keys())
            eos_routers_key_set = frozenset(eos_routers.keys())
            eos_bms_key_set = frozenset(eos_bms.keys())

            # Create a candidate list by incorporating all instances
            eos_instances_key_set = (eos_vms_key_set | eos_routers_key_set |
                                     eos_bms_key_set)

            # Find the networks that are present on EOS, but not in Neutron DB
            nets_to_delete = eos_nets_key_set.difference(db_nets_key_set)

            # Find the VMs that are present on EOS, but not in Neutron DB
            instances_to_delete = eos_instances_key_set.difference(
                db_instances_key_set)

            vms_to_delete = [
                vm for vm in eos_vms_key_set if vm in instances_to_delete]
            routers_to_delete = [
                r for r in eos_routers_key_set if r in instances_to_delete]
            bms_to_delete = [
                b for b in eos_bms_key_set if b in instances_to_delete]

            # Find the Networks that are present in Neutron DB, but not on EOS
            nets_to_update = db_nets_key_set.difference(eos_nets_key_set)

            # Find the VMs that are present in Neutron DB, but not on EOS
            instances_to_update[tenant] = db_instances_key_set.difference(
                eos_instances_key_set)

            try:
                if vms_to_delete:
                    self._rpc.delete_vm_bulk(tenant, vms_to_delete, sync=True)
                if routers_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(
                            tenant,
                            routers_to_delete,
                            constants.InstanceType.ROUTER,
                            sync=True)
                    else:
                        LOG.info(constants.ERR_DVR_NOT_SUPPORTED)

                if bms_to_delete:
                    if self._rpc.bm_and_dvr_supported():
                        self._rpc.delete_instance_bulk(
                            tenant,
                            bms_to_delete,
                            constants.InstanceType.BAREMETAL,
                            sync=True)
                    else:
                        LOG.info(BAREMETAL_NOT_SUPPORTED)

                if nets_to_delete:
                    self._rpc.delete_network_bulk(tenant, nets_to_delete,
                                                  sync=True)
                if nets_to_update:
                    networks = [{
                        'network_id': net_id,
                        'network_name':
                            neutron_nets.get(net_id, {'name': ''})['name'],
                        'shared':
                            neutron_nets.get(net_id,
                                             {'shared': False})['shared'],
                        'segments': self._ndb.get_all_network_segments(context,
                                                                       net_id),
                    }
                        for net_id in nets_to_update
                    ]
                    self._rpc.create_network_bulk(tenant, networks, sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True

        # Now update the VMs
        for tenant in instances_to_update:
            if not instances_to_update[tenant]:
                continue
            try:
                # Filter the ports to only the vms that we are interested
                # in.
                ports_of_interest = {}
                for port in self._ndb.get_all_ports_for_tenant(context,
                                                               tenant):
                    ports_of_interest.update(
                        self._port_dict_representation(port))

                if ports_of_interest:
                    db_vms = db_lib.get_vms(context, tenant)
                    if db_vms:
                        self._rpc.create_instance_bulk(context,
                                                       tenant,
                                                       ports_of_interest,
                                                       db_vms,
                                                       port_profiles,
                                                       sync=True)
            except arista_exc.AristaRpcError:
                LOG.warning(constants.EOS_UNREACHABLE_MSG)
                self._force_sync = True

    def _region_in_sync(self):
        """Checks if the region is in sync with EOS.

           Checks whether the timestamp stored in EOS is the same as the
           timestamp stored locally.
        """
        eos_region_updated_times = self._rpc.get_region_updated_time()
        return eos_region_updated_times and self._region_updated_time and \
            self._region_updated_time == eos_region_updated_times

    def _sync_required(self):
        """"Check whether the sync is required."""
        try:
            # Get the time at which entities in the region were updated.
            # If the times match, then ML2 is in sync with EOS. Otherwise
            # perform a complete sync.
            if not self._force_sync and self._region_in_sync():
                LOG.info(_('OpenStack and EOS are in sync!'))
                return False
        except arista_exc.AristaRpcError:
            LOG.warning(constants.EOS_UNREACHABLE_MSG)
            # Force an update incase of an error.
            self._force_sync = True
        return True

    def _set_region_updated_time(self):
        """Get the region updated time from EOS and store it locally."""
        try:
            self._region_updated_time = self._rpc.get_region_updated_time()
        except arista_exc.AristaRpcError:
            # Force an update incase of an error.
            self._force_sync = True

    def _get_eos_networks(self, eos_tenants, tenant):
        networks = {}
        if eos_tenants and tenant in eos_tenants:
            networks = eos_tenants[tenant]['tenantNetworks']
        return networks

    def _get_eos_vms(self, eos_tenants, tenant):
        vms = {}
        bms = {}
        routers = {}
        if eos_tenants and tenant in eos_tenants:
            vms = eos_tenants[tenant]['tenantVmInstances']
            if 'tenantBaremetalInstances' in eos_tenants[tenant]:
                # Check if baremetal service is supported
                bms = eos_tenants[tenant]['tenantBaremetalInstances']
            if 'tenantRouterInstances' in eos_tenants[tenant]:
                routers = eos_tenants[tenant]['tenantRouterInstances']
        return vms, bms, routers

    def _port_dict_representation(self, port):
        return {port['id']: {'device_owner': port['device_owner'],
                             'device_id': port['device_id'],
                             'name': port['name'],
                             'id': port['id'],
                             'tenant_id': port['tenant_id'],
                             'network_id': port['network_id']}}
