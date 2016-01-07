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

from oslo_log import log as logging

from neutron import manager
from neutron.common import constants as n_const
from neutron.objects.qos import policy as policy_object
from neutron.plugins.common import constants as service_constants
from neutron.services.qos.notification_drivers import qos_base


LOG = logging.getLogger(__name__)


class L3RpcQosNotificationDriver(qos_base.QosServiceNotificationDriverBase):
    """L3 rpc notification driver for QoS."""

    def get_description(self):
        return "L3 Rpc Qos Notification Driver"

    def create_policy(self, context, policy):
        # No need to update agents on create
        pass

    def update_policy(self, context, policy):
        policy_id = policy.get('id')
        binding_objects = policy_object.QosPolicy.\
            get_binding_objects(context, policy_id)
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        for object_type, binding_object in binding_objects:
            if not binding_object:
                continue
            if object_type == 'port':
                plugin = manager.NeutronManager.get_plugin()
                port = plugin.get_port(context, binding_object.get('port_id'))
                device_owner = port.get('device_owner')
                if device_owner == n_const.DEVICE_OWNER_FLOATINGIP:
                    fip_id = port.get('device_id')
                    fip = l3plugin.get_floatingip(context, fip_id)
                    router_id = fip.get('router_id')
                if router_id:
                    l3plugin.notify_router_updated(context, router_id,
                                                   'update_policy')
            elif object_type == 'network':
                pass

    def delete_policy(self, context, policy):
        # No need to update agents on delete
        pass
