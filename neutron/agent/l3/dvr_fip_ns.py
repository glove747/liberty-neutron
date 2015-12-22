# Copyright (c) 2015 Openstack Foundation
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

import os
import traceback

from oslo_utils import excutils

from neutron.agent.l3 import fip_rule_priority_allocator as frpa
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import utils as common_utils
from neutron.common import exceptions as n_exc
from oslo_log import log as logging

from neutron.common.constants import IP_VERSION_4, IP_VERSION_6

LOG = logging.getLogger(__name__)

FIP_NS_PREFIX = 'fip-'
FIP_EXT_DEV_PREFIX = 'fg-'
FIP_2_ROUTER_DEV_PREFIX = 'fpr-'
ROUTER_2_FIP_DEV_PREFIX = namespaces.ROUTER_2_FIP_DEV_PREFIX
# Route Table index for FIPs
FIP_RT_TBL = 16
# Rule Route Table index start for FIPs
FIP_SUBNET_RT_START = 1000000
# Rule Route Table index end for FIPs
FIP_SUBNET_RT_END = FIP_SUBNET_RT_START + 256
FIP_LL_SUBNET = '169.254.30.0/23'
# Rule priority range for FIPs
FIP_PR_START = 32768
FIP_PR_END = FIP_PR_START + 40000


class FipNamespace(namespaces.Namespace):

    def __init__(self, ext_net_id, agent_conf, driver, use_ipv6):
        name = self._get_ns_name(ext_net_id)
        super(FipNamespace, self).__init__(
            name, agent_conf, driver, use_ipv6)

        self._ext_net_id = ext_net_id
        self.agent_conf = agent_conf
        self.driver = driver
        self.use_ipv6 = use_ipv6
        self.agent_gateway_port = None
        self._subscribers = set()
        path = os.path.join(agent_conf.state_path, 'fip-priorities')
        self._rule_priorities = frpa.FipRulePriorityAllocator(path,
                                                              FIP_PR_START,
                                                              FIP_PR_END)
        path = os.path.join(agent_conf.state_path, 'fip-rule-tables')
        self._rule_tables = frpa.FipRuleTableAllocator(path,
                                                          FIP_SUBNET_RT_START,
                                                          FIP_SUBNET_RT_END)
        self._iptables_manager = iptables_manager.IptablesManager(
            namespace=self.get_name(),
            use_ipv6=self.use_ipv6)
        path = os.path.join(agent_conf.state_path, 'fip-linklocal-networks')
        self.local_subnets = lla.LinkLocalAllocator(path, FIP_LL_SUBNET)
        self.destroyed = False

    @classmethod
    def _get_ns_name(cls, ext_net_id):
        return namespaces.build_ns_name(FIP_NS_PREFIX, ext_net_id)

    def get_name(self):
        return self._get_ns_name(self._ext_net_id)

    def get_ext_device_name(self, port_id):
        return (FIP_EXT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_int_device_name(self, router_id):
        return (FIP_2_ROUTER_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def get_rtr_ext_device_name(self, router_id):
        return (ROUTER_2_FIP_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def has_subscribers(self):
        return len(self._subscribers) != 0

    def subscribe(self, router_id):
        is_first = not self.has_subscribers()
        self._subscribers.add(router_id)
        return is_first

    def unsubscribe(self, router_id):
        self._subscribers.discard(router_id)
        return not self.has_subscribers()

    def allocate_rule_priority(self, floating_ip):
        return self._rule_priorities.allocate(floating_ip)

    def deallocate_rule_priority(self, floating_ip):
        self._rule_priorities.release(floating_ip)

    def rule_table_allocate(self, subnet_id):
        return self._rule_tables.allocate(subnet_id)

    def rule_table_deallocate(self, subnet_id):
        self._rule_tables.release(subnet_id)

    def rule_table_keys(self):
        return self._rule_tables.keys()

    def _gateway_updated(self, ex_gw_port, interface_name):
        """Update Floating IP gateway port."""
        LOG.debug(" gateway interface(%s)", interface_name)
        ns_name = self.get_name()

        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs, namespace=ns_name,
                            clean_connections=True)

        for fixed_ip in ex_gw_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'],
                                          self.agent_conf)

        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        # TODO(Carl) mlavelle's work has self.ip_wrapper
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def _gateway_added(self, ex_gw_port, interface_name):
        """Add Floating IP gateway port."""
        LOG.debug("add gateway interface(%s)", interface_name)
        ns_name = self.get_name()
        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'],
                         interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.agent_conf.external_network_bridge,
                         namespace=ns_name,
                         prefix=FIP_EXT_DEV_PREFIX)

        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs, namespace=ns_name,
                            clean_connections=True)

        for fixed_ip in ex_gw_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'],
                                          self.agent_conf)
        # ipd = ip_lib.IPDevice(interface_name, namespace=ns_name)
        # gateway = ipd.route.get_gateway()
        # LOG.debug("DVR: gateway exist: %s", gateway)
        # if not gateway:
        #     for subnet in ex_gw_port['subnets']:
        #         gw_ip = subnet.get('gateway_ip')
        #         if gw_ip:
        #             ipd.route.add_gateway(gw_ip)

        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        # TODO(Carl) mlavelle's work has self.ip_wrapper
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def create(self):
        # TODO(Carl) Get this functionality from mlavelle's namespace baseclass
        LOG.debug("DVR: add fip namespace: %s", self.name)
        ip_wrapper_root = ip_lib.IPWrapper()
        ip_wrapper = ip_wrapper_root.ensure_namespace(self.get_name())
        # Somewhere in the 3.19 kernel timeframe ip_nonlocal_bind was
        # changed to be a per-namespace attribute.  To be backwards
        # compatible we need to try both if at first we fail.
        try:
            ip_wrapper.netns.execute(['sysctl',
                                      '-w',
                                      'net.ipv4.ip_nonlocal_bind=1'],
                                     log_fail_as_error=False,
                                     run_as_root=True)
        except RuntimeError:
            LOG.debug('DVR: fip namespace (%s) does not support setting '
                      'net.ipv4.ip_nonlocal_bind, trying in root namespace',
                      self.name)
            ip_wrapper_root.netns.execute(['sysctl',
                                           '-w',
                                           'net.ipv4.ip_nonlocal_bind=1'],
                                          run_as_root=True)

        ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        if self.use_ipv6:
            ip_wrapper.netns.execute(['sysctl', '-w',
                                      'net.ipv6.conf.all.forwarding=1'])

        # no connection tracking needed in fip namespace
        self._iptables_manager.ipv4['raw'].add_rule('PREROUTING',
                                                    '-j CT --notrack')
        self._iptables_manager.apply()

    def delete(self):
        self.destroyed = True
        ip_wrapper = ip_lib.IPWrapper(namespace=self.name)
        for d in ip_wrapper.get_devices(exclude_loopback=True):
            if d.name.startswith(FIP_2_ROUTER_DEV_PREFIX):
                # internal link between IRs and FIP NS
                ip_wrapper.del_veth(d.name)
            elif d.name.startswith(FIP_EXT_DEV_PREFIX):
                # single port from FIP NS to br-ext
                # TODO(carl) Where does the port get deleted?
                LOG.debug('DVR: unplug: %s', d.name)
                ext_net_bridge = self.agent_conf.external_network_bridge
                self.driver.unplug(d.name,
                                   bridge=ext_net_bridge,
                                   namespace=self.name,
                                   prefix=FIP_EXT_DEV_PREFIX)
        self.agent_gateway_port = None

        # TODO(mrsmith): add LOG warn if fip count != 0
        LOG.debug('DVR: destroy fip namespace: %s', self.name)
        super(FipNamespace, self).delete()

    def update_gateway_port(self, agent_gateway_port):
        """Update Floating IP gateway port.

           Request port update from Plugin then adds gateway port.
        """
        self.agent_gateway_port = agent_gateway_port

        iface_name = self.get_ext_device_name(agent_gateway_port['id'])
        self._gateway_updated(agent_gateway_port, iface_name)

    def create_gateway_port(self, agent_gateway_port):
        """Create Floating IP gateway port.

           Request port creation from Plugin then creates
           Floating IP namespace and adds gateway port.
        """
        self.agent_gateway_port = agent_gateway_port

        self.create()

        iface_name = self.get_ext_device_name(agent_gateway_port['id'])
        self._gateway_added(agent_gateway_port, iface_name)

    def _internal_ns_interface_added(self, ip_cidr,
                                    interface_name, ns_name):
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        ip_wrapper.netns.execute(['ip', 'addr', 'add',
                                  ip_cidr, 'dev', interface_name])

    def create_rtr_2_fip_link(self, ri):
        """Create interface between router and Floating IP namespace."""
        LOG.debug("Create FIP link interfaces for router %s", ri.router_id)
        rtr_2_fip_name = self.get_rtr_ext_device_name(ri.router_id)
        fip_2_rtr_name = self.get_int_device_name(ri.router_id)
        fip_ns_name = self.get_name()

        # add link local IP to interface
        if ri.rtr_fip_subnet is None:
            ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        ip_wrapper = ip_lib.IPWrapper(namespace=ri.ns_name)
        device_exists = ip_lib.device_exists(rtr_2_fip_name,
                                             namespace=ri.ns_name)
        if not device_exists:
            int_dev = ip_wrapper.add_veth(rtr_2_fip_name,
                                          fip_2_rtr_name,
                                          fip_ns_name)
            self._internal_ns_interface_added(str(rtr_2_fip),
                                              rtr_2_fip_name,
                                              ri.ns_name)
            self._internal_ns_interface_added(str(fip_2_rtr),
                                              fip_2_rtr_name,
                                              fip_ns_name)
            if self.agent_conf.network_device_mtu:
                int_dev[0].link.set_mtu(self.agent_conf.network_device_mtu)
                int_dev[1].link.set_mtu(self.agent_conf.network_device_mtu)
            int_dev[0].link.set_up()
            int_dev[1].link.set_up()

        # add default route for the link local interface
        device = ip_lib.IPDevice(rtr_2_fip_name, namespace=ri.ns_name)
        device.route.add_gateway(str(fip_2_rtr.ip), table=FIP_RT_TBL)
        #setup the NAT rules and chains
        ri._handle_fip_nat_rules(rtr_2_fip_name)

    def scan_fip_ports(self, ri):
        # don't scan if not dvr or count is not None
        if ri.dist_fip_count is not None:
            return

        # scan system for any existing fip ports
        ri.dist_fip_count = 0
        rtr_2_fip_interface = self.get_rtr_ext_device_name(ri.router_id)
        if ip_lib.device_exists(rtr_2_fip_interface, namespace=ri.ns_name):
            device = ip_lib.IPDevice(rtr_2_fip_interface, namespace=ri.ns_name)
            existing_cidrs = [addr['cidr'] for addr in device.addr.list()]
            fip_cidrs = [c for c in existing_cidrs if
                         common_utils.is_cidr_host(c)]
            for fip_cidr in fip_cidrs:
                fip_ip = fip_cidr.split('/')[0]
                rule_pr = self._rule_priorities.allocate(fip_ip)
                ri.floating_ips_dict[fip_ip] = rule_pr
            ri.dist_fip_count = len(fip_cidrs)

    def update_fip_gateway_rule(self, fip_agent_port):
        # update subnet rule and rule table
        try:
            LOG.debug("DVR: update fip-xxx ns subnets's rule")
            subnet_ids = [fixed_ip['subnet_id'] for
                          fixed_ip in fip_agent_port['fixed_ips']]
            rule_table_keys = self.rule_table_keys()
            LOG.debug('subnet_ids: %s, rule_table_keys: %s',
                      subnet_ids,
                      rule_table_keys)
            for subnet_id in rule_table_keys:
                # to delete
                if subnet_id not in subnet_ids:
                    try:
                        LOG.debug("DVR: del fipns subnets's rule, "
                                  "subnet_id: %s", subnet_id)
                        priority = str(self.rule_table_allocate(subnet_id))
                        self._delete_fip_gateway_rule(priority)

                        fip_fg_name = self. \
                            get_ext_device_name(fip_agent_port['id'])
                        fip_ns_name = self.get_name()
                        device = ip_lib.IPDevice(fip_fg_name,
                                                 namespace=fip_ns_name)
                        gateway = device.route.get_gateway()
                        if gateway:
                            gateway = gateway.get('gateway')
                            try:
                                device.route.delete_gateway(gateway,
                                                            table=priority)
                            except n_exc.DeviceNotFoundError:
                                pass
                        self.rule_table_deallocate(subnet_id)
                    except Exception:
                        err_msg = "del_fip_gateway_rule error %s" % \
                                  traceback.format_exc()
                        LOG.exception(err_msg)
        except Exception:
            err_msg = "update_fip_gateway_rule error %s" % \
                      traceback.format_exc()
            LOG.exception(err_msg)
            raise n_exc.FloatingIpSetupException(err_msg)

    def _delete_fip_gateway_rule(self, priority):
        def _delete(ip_version):
            fip_ns_name = self.get_name()
            ip_rule = ip_lib.IPRule(namespace=fip_ns_name)
            rules = ip_rule.rule.list_rules(ip_version)
            LOG.debug("DVR: ip %s rules: %s, priority: %s",
                      ip_version, rules, priority)
            if rules:
                to_delete_rules = filter(lambda x:
                                         x['priority'] == priority,
                                         rules)
                if any(to_delete_rules):
                    to_delete_ip = to_delete_rules[0]['from']
                    ip_rule.rule.delete(ip=to_delete_ip,
                                        table=priority,
                                        priority=priority)
        _delete(IP_VERSION_4)
        _delete(IP_VERSION_6)

    @common_utils.synchronized("update_fip_arp_entry")
    def _update_fip_arp_entry(self, fip_gateway_port_id, fip, mac, operation):
        def _delete(fip):
            try:
                while True:
                    device.neigh.delete(fip)
                    LOG.debug("DVR: deleted fip arp entry, %s .", fip)
            except Exception:
                pass
        try:
            interface_name = self.get_ext_device_name(fip_gateway_port_id)
            if ip_lib.device_exists(interface_name,
                                    namespace=self._get_ns_name()):
                device = ip_lib.IPDevice(interface_name,
                                         namespace=self._get_ns_name())
                if operation == 'add':
                    _delete(fip)
                    device.neigh.add(fip, mac)
                    LOG.debug("DVR: added fip arp entry, %s %s .", fip, mac)
                elif operation == 'delete':
                    _delete(fip)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("DVR: Failed updating fip arp entry")

    def add_fip_arp_entry(self, fip_gateway_port_id, arp_dict):
        fip = arp_dict['floating_ip_address']
        mac = arp_dict['mac_address']
        self._update_fip_arp_entry(fip_gateway_port_id, fip, mac, 'add')

    def del_fip_arp_entry(self, fip_gateway_port_id, arp_dict):
        fip = arp_dict['floating_ip_address']
        self._update_fip_arp_entry(fip_gateway_port_id, fip, None, 'del')

