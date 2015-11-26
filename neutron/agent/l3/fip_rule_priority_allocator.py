# Copyright 2015 IBM Corporation
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

from neutron.agent.l3.item_allocator import ItemAllocator
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class FipPriority(object):
    def __init__(self, index):
        self.index = index

    def __repr__(self):
        return str(self.index)

    def __hash__(self):
        return hash(self.__repr__())

    def __eq__(self, other):
        if isinstance(other, FipPriority):
            return (self.index == other.index)
        else:
            return False


class FipRulePriorityAllocator(ItemAllocator):
    """Manages allocation of floating ips rule priorities.
        IP rule priorities assigned to DVR floating IPs need
        to be preserved over L3 agent restarts.
        This class provides an allocator which saves the prirorities
        to a datastore which will survive L3 agent restarts.
    """
    def __init__(self, data_store_path, priority_rule_start,
                 priority_rule_end):
        """Create the necessary pool and create the item allocator
            using ',' as the delimiter and FipRulePriorityAllocator as the
            class type
        """
        pool = set(FipPriority(str(s)) for s in range(priority_rule_start,
                                                      priority_rule_end))

        super(FipRulePriorityAllocator, self).__init__(data_store_path,
                                                       FipPriority,
                                                      pool)


class RuleTable(object):
    def __init__(self, index):
        self.index = index

    def __repr__(self):
        return str(self.index)

    def __hash__(self):
        return hash(self.__repr__())

    def __eq__(self, other):
        if isinstance(other, RuleTable):
            return self.index == other.index
        else:
            return False


class FipRuleTableAllocator(ItemAllocator):
    """Manages allocation of floating ips rule tables.
        IP rule table assigned to DVR floating IPs need
        to be preserved over L3 agent restarts.
        This class provides an allocator which saves the tables
        to a datastore which will survive L3 agent restarts.
    """

    def __init__(self, data_store_path, priority_rule_start,
                 priority_rule_end):
        """Create the necessary pool and create the item allocator
            using ',' as the delimiter and FipRulePriorityAllocator as the
            class type
        """
        pool = set(RuleTable(str(s)) for s in range(priority_rule_start,
                                                    priority_rule_end))

        super(FipRuleTableAllocator, self).__init__(data_store_path,
                                                    RuleTable,
                                                    pool)

    def allocate(self, key):
        LOG.debug('allocate key: %s, allocations: %s, remembered: %s, pool: %s',
                  key, self.allocations, self.remembered, self.pool)
        if key in self.allocations:
            return self.allocations[key]
        return super(FipRuleTableAllocator, self).allocate(key)

    def release(self, key):
        LOG.debug('release key: %s, allocations: %s, remembered: %s, pool: %s',
                  key, self.allocations, self.remembered, self.pool)
        if key in self.remembered:
            self.remembered.pop(key)
        super(FipRuleTableAllocator, self).release(key)

    def keys(self):
        return self.allocations.keys() + self.remembered.keys()

