# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

from oslo_log import log as logging

from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_common
from neutron.objects.qos import policy as policy_object

LOG = logging.getLogger(__name__)


class DVR_policy_db_mixin(object):
    """Mixin class to add qos policy methods to db_base_plugin_v2."""

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy(self, context, policy_id, fields=None):
        return self._get_policy_obj(context, policy_id)

    def _get_policy_obj(self, context, policy_id):
        obj = policy_object.QosPolicy.get_by_id(context, policy_id)
        if obj is None:
            raise n_exc.QosPolicyNotFound(policy_id=policy_id)
        return obj
