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

from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db.models import allowed_address_pair as aap_models
from neutron.db.models import segment as segments_model
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2, segments_db
from neutron.db import securitygroups_db as sec_db
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import models as ml2_models
from neutron_lib.plugins.ml2 import api
from sqlalchemy import literal

from networking_arista.common import db as db_models

VLAN_SEGMENTATION = 'vlan'


def remember_tenant(context, project_id):
    """Stores a tenant information in repository.

    :param context: context of the transaction
    :param project_id: globally unique project identifier
    """
    session = context.session
    with session.begin(subtransactions=True):
        # Tenant might not be unique, but then we just have duplicates in the
        # "set".
        project = (session.query(db_models.AristaProvisionedProjects).
                   filter_by(project_id=project_id).first())
        if not project:
            project = db_models.AristaProvisionedProjects(
                                            project_id=project_id)
            session.add(project)


def forget_tenant(context, project_id):
    """Removes a tenant information from repository.

    :param context: context of the transaction
    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session
    return session.query(db_models.AristaProvisionedProjects). \
        filter_by(project_id=project_id). \
        delete()


def get_all_tenants(context):
    """Returns a list of all tenants stored in repository.

    :param context: context of the transaction
    """
    return context.session.query(db_models.AristaProvisionedProjects)


def num_provisioned_tenants(context):
    """Returns number of tenants stored in repository.

    :param context: context of the transaction
    """
    return get_all_tenants(context).count()


def remember_vm(context, vm_id, host_id, port_id, network_id, project_id):
    """Stores all relevant information about a VM in repository.

    :param context: context of the transaction
    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session
    with session.begin(subtransactions=True):
        vm = db_models.AristaProvisionedVms(
            vm_id=vm_id,
            host_id=host_id,
            port_id=port_id,
            network_id=network_id,
            project_id=project_id)
        session.add(vm)


def forget_all_ports_for_network(context, net_id):
    """Removes all ports for a given network from repository.

    :param net_id: globally unique network ID
    """
    return context.session.query(db_models.AristaProvisionedVms). \
        filter_by(network_id=net_id).delete()


def update_port(context, vm_id, host_id, port_id, network_id, project_id):
    """Updates the port details in the database.

    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the new host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session
    port = session.query(db_models.AristaProvisionedVms).filter_by(
        port_id=port_id).first()
    if port:
        # Update the VM's host id
        port.host_id = host_id
        port.vm_id = vm_id
        port.network_id = network_id
        port.project_id = project_id


def forget_port(context, port_id, host_id):
    """Deletes the port from the database

    :param port_id: globally unique port ID that connects VM to network
    :param host_id: host to which the port is bound to
    """
    return context.session.query(db_models.AristaProvisionedVms).filter_by(
        port_id=port_id,
        host_id=host_id).delete()


def remember_network_segment(context, project_id,
                             network_id, segmentation_id, segment_id):
    """Stores all relevant information about a Network in repository.

    :param project_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    :param segmentation_id: segmentation id that is assigned to the network
    :param segment_id: globally unique neutron network segment identifier
    """
    session = context.session
    with session.begin(subtransactions=True):
        net = db_models.AristaProvisionedNets(
            project_id=project_id,
            id=segment_id,
            network_id=network_id,
            segmentation_id=segmentation_id)
        session.add(net)


def forget_network_segment(context, project_id, network_id, segment_id=None):
    """Deletes all relevant information about a Network from repository.

    :param project_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    :param segment_id: globally unique neutron network segment identifier
    """
    filters = {
        'project_id': project_id,
        'network_id': network_id
    }
    if segment_id:
        filters['id'] = segment_id

    return context.session.query(db_models.AristaProvisionedNets). \
        filter_by(**filters).delete()


def get_segmentation_id(context, project_id, network_id):
    """Returns Segmentation ID (VLAN) associated with a network.

    :param project_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    """
    session = context.session
    return session.query(db_models.AristaProvisionedNets.segmentation_id). \
        filter_by(project_id=project_id,
                  network_id=network_id).first()


def get_segmentation_id_by_segment_id(context, segment_id):
    """Returns Segmentation ID (VLAN) associated with a segment.

    :param project_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    """
    session = context.session
    return session.query(db_models.AristaProvisionedNets.segmentation_id). \
        filter_by(id=segment_id).first()


def is_vm_provisioned(context, vm_id, host_id, port_id,
                      network_id, tenant_id):
    """Checks if a VM is already known to EOS

    :returns: True, if yes; False otherwise.
    :param vm_id: globally unique identifier for VM instance
    :param host_id: ID of the host where the VM is placed
    :param port_id: globally unique port ID that connects VM to network
    :param network_id: globally unique neutron network identifier
    :param tenant_id: globally unique neutron tenant identifier
    """
    session = context.session
    return session.query(literal(True)).filter(
        session.query(db_models.AristaProvisionedVms).
        filter_by(tenant_id=tenant_id,
                  vm_id=vm_id,
                  port_id=port_id,
                  network_id=network_id,
                  host_id=host_id).exists()).scalar()


def is_port_provisioned(context, port_id, host_id=None):
    """Checks if a port is already known to EOS

    :returns: True, if yes; False otherwise.
    :param port_id: globally unique port ID that connects VM to network
    :param host_id: host to which the port is bound to
    """

    filters = {
        'port_id': port_id
    }
    if host_id:
        filters['host_id'] = host_id

    session = context.session

    return session.query(literal(True)).filter(
        session.query(db_models.AristaProvisionedVms).
        filter_by(**filters).exists()).scalar()


def is_network_provisioned(context,
                           project_id, network_id, segmentation_id=None,
                           segment_id=None):
    """Checks if a networks is already known to EOS

    :returns: True, if yes; False otherwise.
    :param project_id: globally unique neutron tenant identifier
    :param network_id: globally unique neutron network identifier
    :param segment_id: globally unique neutron network segment identifier
    """
    filters = {'project_id': project_id,
               'network_id': network_id}
    if segmentation_id:
        filters['segmentation_id'] = segmentation_id
    if segment_id:
        filters['id'] = segment_id

    query = context.session.query

    return query(literal(True)).filter(
        query(db_models.AristaProvisionedNets).
        filter_by(**filters).exists()).scalar()


def is_tenant_provisioned(context, project_id):
    """Checks if a tenant is already known to EOS

    :returns: True, if yes; False otherwise.
    :param project_id: globally unique neutron tenant identifier
    """
    query = context.session.query

    return query(literal(True)).filter(
        query(db_models.AristaProvisionedProjects).
        filter_by(project_id=project_id).exists()).scalar()


def num_nets_provisioned(context, project_id):
    """Returns number of networks for a given tennat.

    :param project_id: globally unique neutron tenant identifier
    """
    return context.session.query(db_models.AristaProvisionedNets). \
        filter_by(project_id=project_id).count()


def num_vms_provisioned(context, project_id):
    """Returns number of VMs for a given tennat.

    :param project_id: globally unique neutron tenant identifier
    """
    return context.session.query(db_models.AristaProvisionedVms). \
        filter_by(project_id=project_id).count()


def get_networks(context, project_id):
    """Returns all networks for a given tenant in EOS-compatible format.

    See AristaRPCWrapper.get_network_list() for return value format.
    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session

    model = db_models.AristaProvisionedNets
    if project_id != 'any':
        all_nets = (session.query(model).
                    filter(model.project_id == project_id,
                           model.segmentation_id.isnot(None)))
    else:
        all_nets = (session.query(model).
                    filter(model.segmentation_id.isnot(None)))

    res = dict(
        (net.network_id, net.eos_network_representation(
            VLAN_SEGMENTATION))
        for net in all_nets
    )
    return res


def get_vms(context, project_id):
    """Returns all VMs for a given tenant in EOS-compatible format.

    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session
    model = db_models.AristaProvisionedVms
    all_ports = (session.query(model).
                 filter(model.project_id == project_id,
                        model.host_id.isnot(None),
                        model.vm_id.isnot(None),
                        model.network_id.isnot(None),
                        model.port_id.isnot(None)))
    ports = {}
    for port in all_ports:
        if port.port_id not in ports:
            ports[port.port_id] = port.eos_port_representation()
        else:
            ports[port.port_id]['hosts'].append(port.host_id)

    vm_dict = dict()

    def eos_vm_representation(port):
        return {u'vmId': port['deviceId'],
                u'baremetal_instance': False,
                u'ports': [port]}

    for port in ports.values():
        deviceId = port['deviceId']
        if deviceId in vm_dict:
            vm_dict[deviceId]['ports'].append(port)
        else:
            vm_dict[deviceId] = eos_vm_representation(port)
    return vm_dict


def are_ports_attached_to_network(context, net_id):
    """Returns all records associated with network in EOS-compatible format.

    :param net_id: globally unique network ID
    """
    model = db_models.AristaProvisionedVms
    query = context.session.query
    return query(literal(True)).filter(
        query(model).filter(model.network_id == net_id).exists()).scalar()


def get_ports(context, project_id=None):
    """Returns all ports of VMs in EOS-compatible format.

    :param project_id: globally unique neutron tenant identifier
    """
    session = context.session
    model = db_models.AristaProvisionedVms
    if project_id:
        all_ports = (session.query(model).
                     filter(model.project_id == project_id,
                            model.host_id.isnot(None),
                            model.vm_id.isnot(None),
                            model.network_id.isnot(None),
                            model.port_id.isnot(None)))
    else:
        all_ports = (session.query(model).
                     filter(model.project_id.isnot(None),
                            model.host_id.isnot(None),
                            model.vm_id.isnot(None),
                            model.network_id.isnot(None),
                            model.port_id.isnot(None)))
    ports = {}
    for port in all_ports:
        if port.port_id not in ports:
            ports[port.port_id] = port.eos_port_representation()
        ports[port.port_id]['hosts'].append(port.host_id)

    return ports


def get_tenants(context):
    """Returns list of all tenants in EOS-compatible format."""
    session = context.session
    model = db_models.AristaProvisionedProjects
    all_tenants = session.query(model)
    res = dict(
        (tenant.project_id, tenant.eos_tenant_representation())
        for tenant in all_tenants
    )
    return res


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
    segments = (session.query(segments_model.NetworkSegment,
                              ml2_models.PortBindingLevel).
                join(ml2_models.PortBindingLevel).
                filter_by(port_id=port_id).
                order_by(ml2_models.PortBindingLevel.level).
                all())
    return [segment[0] for segment in segments]


@db_api.retry_if_session_inactive()
def select_ips_for_remote_group(context, remote_group_ids):
    """Find all ips for a remote group - copied from neutron

    This function is originally part of the class SecurityGroupServerRpcMixin,
    see neutron/db/securitygroups_rpc_base.py, should be replaced when
    a better method of finding sg group membership has been implemented
    in this driver.
    """
    ips_by_group = {}
    if not remote_group_ids:
        return ips_by_group
    for remote_group_id in remote_group_ids:
        ips_by_group[remote_group_id] = set()

    ip_port = models_v2.IPAllocation.port_id
    sg_binding_port = sg_models.SecurityGroupPortBinding.port_id
    sg_binding_sgid = sg_models.SecurityGroupPortBinding.security_group_id

    # Join the security group binding table directly to the IP allocation
    # table instead of via the Port table skip an unnecessary intermediary
    query = context.session.query(sg_binding_sgid,
                                  models_v2.IPAllocation.ip_address,
                                  aap_models.AllowedAddressPair.ip_address)
    query = query.join(models_v2.IPAllocation,
                       ip_port == sg_binding_port)
    # Outerjoin because address pairs may be null and we still want the
    # IP for the port.
    query = query.outerjoin(
        aap_models.AllowedAddressPair,
        sg_binding_port == aap_models.AllowedAddressPair.port_id)
    query = query.filter(sg_binding_sgid.in_(remote_group_ids))
    # Each allowed address pair IP record for a port beyond the 1st
    # will have a duplicate regular IP in the query response since
    # the relationship is 1-to-many. Dedup with a set
    for security_group_id, ip_address, allowed_addr_ip in query:
        ips_by_group[security_group_id].add(ip_address)
        if allowed_addr_ip:
            ips_by_group[security_group_id].add(allowed_addr_ip)
    return ips_by_group


class NeutronNets(db_base_plugin_v2.NeutronDbPluginV2,
                  sec_db.SecurityGroupDbMixin):
    """Access to Neutron DB.

    Provides access to the Neutron Data bases for all provisioned
    networks as well ports. This data is used during the synchronization
    of DB between ML2 Mechanism Driver and Arista EOS
    Names of the networks and ports are not stroed in Arista repository
    They are pulled from Neutron DB.
    """

    def __init__(self):
        pass

    def get_all_networks_for_tenant(self, context, project_id):
        filters = {'project_id': [project_id]}
        return super(NeutronNets,
                     self).get_networks(context, filters=filters) or []

    def get_all_networks(self, context, fields=None):
        return super(NeutronNets, self).get_networks(context,
                                                     fields=fields) or []

    def get_all_ports(self, context, filters=None):
        return super(NeutronNets, self).get_ports(context,
                                                  filters=filters) or []

    def get_all_ports_for_tenant(self, context, project_id):
        filters = {'project_id': [project_id]}
        return super(NeutronNets,
                     self).get_ports(context, filters=filters) or []

    def get_shared_network_owner_id(self, context, network_id):
        filters = {'id': [network_id]}
        nets = self.get_networks(filters=filters, context=context) or []
        segments = segments_db.get_network_segments(context, network_id)

        if not nets or not segments:
            return
        if (nets[0]['shared'] and
                segments[0][api.NETWORK_TYPE] == p_const.TYPE_VLAN):
            return nets[0]['project_id']

    def get_network_segments(self, context, network_id, dynamic=False):
        segments = segments_db.get_network_segments(context, network_id,
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

    def get_segment_by_id(self, context, segment_id):
        return segments_db.get_segment_by_id(context,
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
