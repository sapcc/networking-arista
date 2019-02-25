# Copyright 2019 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
from alembic import op

"""Queens migration: rename tenant_id to project_id

Revision ID: 18fb0a44f926
Revises: 47036dc8697a
Create Date: 2019-02-25 12:55:09.418252

"""

# revision identifiers, used by Alembic.
revision = '18fb0a44f926'
down_revision = '47036dc8697a'
branch_labels = None
depends_on = None


def upgrade():
    # drop all tenant_id indices
    old_tables = ['arista_provisioned_nets',
                  'arista_provisioned_vms',
                  'arista_provisioned_tenants']
    for table_name in old_tables:
        idx_name = 'ix_{}_tenant_id'.format(table_name)
        op.drop_index(idx_name, table_name)

    # rename table arista_provisioned_tenants -> arista_provisioned_projects
    op.rename_table('arista_provisioned_tenants', 'arista_provisioned_projects')

    # rename column tenant_id -> project_id
    tables = ['arista_provisioned_nets',
              'arista_provisioned_vms',
              'arista_provisioned_projects']
    for table_name in tables:
        op.alter_column(table_name, 'tenant_id', new_column_name='project_id')

        # create index
        idx_name = 'ix_{}_project_id'.format(table_name)
        op.create_index(idx_name, table_name, ['project_id'])
