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

from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.db.securitygroups_rpc_base import SecurityGroupServerRpcMixin
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import db as segments_db
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import models as ml2_models

from networking_arista.common import utils
from sqlalchemy import literal


VLAN_SEGMENTATION = 'vlan'


def get_instance_ports(context, tenant_id, manage_fabric=True,
                       managed_physnets=None):
    """Returns all instance ports for a given tenant."""
    session = context.session()
    with session.begin():
        # hack for pep8 E711: comparison to None should be
        # 'if cond is not None'
        none = None
        port_model = models_v2.Port
        binding_level_model = ml2_models.PortBindingLevel
        segment_model = ml2_models.NetworkSegment
        all_ports = (session
                     .query(port_model, binding_level_model, segment_model)
                     .join(binding_level_model)
                     .join(segment_model)
                     .filter(port_model.tenant_id == tenant_id,
                             binding_level_model.host != none,
                             port_model.device_id != none,
                             port_model.network_id != none))
        if not manage_fabric:
            all_ports = all_ports.filter(
                segment_model.physical_network != none)
        if managed_physnets is not None:
            managed_physnets.append(None)
            all_ports = all_ports.filter(segment_model.physical_network.in_(
                managed_physnets))

        def eos_port_representation(port):
            return {u'portId': port.id,
                    u'deviceId': port.device_id,
                    u'hosts': set([bl.host for bl in port.binding_levels]),
                    u'networkId': port.network_id}

        ports = {}
        for port in all_ports:
            if not utils.supported_device_owner(port.Port.device_owner):
                continue
            ports[port.Port.id] = eos_port_representation(port.Port)

        vm_dict = dict()

        def eos_vm_representation(port):
            return {u'vmId': port['deviceId'],
                    u'baremetal_instance': False,
                    u'ports': {port['portId']: port}}

        for port in ports.values():
            deviceId = port['deviceId']
            if deviceId in vm_dict:
                vm_dict[deviceId]['ports'][port['portId']] = port
            else:
                vm_dict[deviceId] = eos_vm_representation(port)
        return vm_dict


def get_instances(context, tenant):
    """Returns set of all instance ids that may be relevant on CVX."""
    session = context.session
    with session.begin():
        port_model = models_v2.Port
        return set(device_id[0] for device_id in
                   session.query(port_model.device_id).
                   filter(port_model.tenant_id == tenant).distinct())


def tenant_provisioned(context, tid):
    """Returns true if any networks or ports exist for a tenant."""
    session = context.session
    with session.begin():
        network_model = models_v2.Network
        port_model = models_v2.Port
        res = bool(
            session.query(network_model).filter_by(tenant_id=tid).count() or
            session.query(port_model).filter_by(tenant_id=tid).count()
    )
    return res


def get_tenants(context):
    """Returns list of all project/tenant ids that may be relevant on CVX."""
    session = context.session
    project_ids = set()
    with session.begin():
        network_model = models_v2.Network
        project_ids |= set(pid[0] for pid in
                           session.query(network_model.project_id).distinct())
        port_model = models_v2.Port
        project_ids |= set(pid[0] for pid in
                           session.query(port_model.project_id).distinct())
    return project_ids


def _make_port_dict(record):
    """Make a dict from the BM profile DB record."""
    return {'port_id': record.port_id,
            'host_id': record.host,
            'vnic_type': record.vnic_type,
            'profile': record.profile}


def get_all_baremetal_ports(context):
    """Returns a list of all ports that belong to baremetal hosts."""
    session = context.session
    query = session.query(ml2_models.PortBinding)
    bm_ports = query.filter_by(vnic_type='baremetal', vif_type='other').all()

    return {bm_port.port_id: _make_port_dict(bm_port)
            for bm_port in bm_ports}


def get_all_portbindings(context):
    """Returns a list of all ports bindings."""
    session = context.session
    ports = session.query(ml2_models.PortBinding).all()
    return {port.port_id: _make_port_dict(port)
            for port in ports}


def get_port_binding_level(context, filters):
    """Returns entries from PortBindingLevel based on the specified filters."""
    return context.session.query(ml2_models.PortBindingLevel). \
        filter_by(**filters). \
        order_by(ml2_models.PortBindingLevel.level). \
        all()


def get_network_segments_by_port_id(context, port_id):
    session = context.session
    segments = (session.query(ml2_models.NetworkSegment,
                              ml2_models.PortBindingLevel).
                join(ml2_models.PortBindingLevel).
                filter_by(port_id=port_id).
                order_by(ml2_models.PortBindingLevel.level).
                all())
    return [segment[0] for segment in segments]


class NeutronNets(db_base_plugin_v2.NeutronDbPluginV2,
                  SecurityGroupServerRpcMixin):
    """Access to Neutron DB.

    Provides access to the Neutron Data bases for all provisioned
    networks as well ports. This data is used during the synchronization
    of DB between ML2 Mechanism Driver and Arista EOS
    Names of the networks and ports are not stroed in Arista repository
    They are pulled from Neutron DB.
    """

    def __init__(self):
        pass

    def get_all_networks_for_tenant(self, context, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_networks(context, filters=filters) or []

    def get_all_networks(self, context, fields=None):
        return super(NeutronNets, self).get_networks(context,
                                                     fields=fields) or []

    def get_all_ports(self, context, filters=None):
        return super(NeutronNets, self).get_ports(context,
                                                  filters=filters) or []

    def get_all_ports_for_tenant(self, context, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_ports(context, filters=filters) or []

    def get_shared_network_owner_id(self, context, network_id):
        filters = {'id': [network_id]}
        nets = self.get_networks(filters=filters, context=context) or []
        segments = segments_db.get_network_segments(context.session,
                                                    network_id)
        if not nets or not segments:
            return
        if (nets[0]['shared'] and
                segments[0][driver_api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return nets[0]['tenant_id']

    def get_network_segments(self, context, network_id, dynamic=False):
        db_session = context.session
        segments = segments_db.get_network_segments(db_session, network_id,
                                                    filter_dynamic=dynamic)
        if dynamic:
            for segment in segments:
                segment['is_dynamic'] = True
        return segments

    def get_all_network_segments(self, context, network_id):
        segments = self.get_network_segments(context, network_id)
        segments += self.get_network_segments(context, network_id,
                                              dynamic=True)
        return segments

    def get_segment_by_id(self, session, segment_id):
        return segments_db.get_segment_by_id(session,
                                             segment_id)

    def get_network_from_net_id(self, context, network_id):
        filters = {'id': [network_id]}
        return super(NeutronNets,
                     self).get_networks(context,
                                        filters=filters) or []

    def get_subnet_info(self, context, subnet_id):
        return self.get_subnet(context, subnet_id)

    def get_subnet(self, context, subnet_id):
        return super(NeutronNets, self). \
                   get_subnet(context, subnet_id) or {}

    def get_all_security_gp_to_port_bindings(self, context, filters=None):
        return super(NeutronNets, self)._get_port_security_group_bindings(
            context, filters=filters) or []

    def get_security_gp_to_port_bindings(self, context, sec_gp_id):
        filters = {'security_group_id': [sec_gp_id]}
        return super(NeutronNets, self)._get_port_security_group_bindings(
            context, filters=filters) or []

    def get_security_groups(self, context, filters=None):
        sgs = super(NeutronNets,
                    self).get_security_groups(context, filters=filters) or []
        sgs_all = {}
        if sgs:
            for s in sgs:
                sgs_all[s['id']] = s
        return sgs_all
