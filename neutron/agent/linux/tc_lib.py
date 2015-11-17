# Copyright 2012 OpenStack Foundation
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
import re

from neutron.agent.common import utils
from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)


def ip_to_hex(ip_or_cidr):
    return ''.join(
        ['%x' % int(i) for i in ip_or_cidr.split('/')[0].split('.')])

def cidr_to_ip(ip_or_cidr):
    return ip_or_cidr.split('/')[0]

class TcWrapper(object):
    def __init__(self, namespace=None, log_fail_as_error=True):
        self.namespace = namespace
        self.log_fail_as_error = log_fail_as_error
        self.tc = TcCommand(self)

    @classmethod
    def _execute(cls, options, command, args, run_as_root=False,
                 namespace=None, log_fail_as_error=True, shell=False):
        opt_list = ['-%s' % o for o in options]
        cmd = ip_lib.add_namespace_to_cmd([command], namespace)
        cmd = cmd + opt_list + list(args)
        return utils.execute(cmd, run_as_root=run_as_root,
                             log_fail_as_error=log_fail_as_error,
                             shell=shell)

    def _run(self, options, command, args, shell=False):
        if self.namespace:
            return self._as_root(options, command, args, shell=shell)
        else:
            return self._execute(options, command, args,
                                 log_fail_as_error=self.log_fail_as_error,
                                 shell=shell)

    def _as_root(self, options, command, args,
                 use_root_namespace=False, shell=False):
        namespace = self.namespace if not use_root_namespace else None

        return self._execute(options, command, args, run_as_root=True,
                             namespace=namespace,
                             log_fail_as_error=self.log_fail_as_error,
                             shell=shell)

class TcCommandBase(object):
    COMMAND = ''

    def __init__(self, parent):
        self._parent = parent

    def _run(self, options, args, shell=False):
        return self._parent._run(options, self.COMMAND, args, shell=shell)

    def _as_root(self, options, args, use_root_namespace=False, shell=False):
        return self._parent._as_root(options,
                                     self.COMMAND,
                                     args,
                                     use_root_namespace=use_root_namespace,
                                     shell=shell)

class TcCommand(TcCommandBase):
    COMMAND = 'tc'

    def has_root_ingress(self, dev):
        # command example:
        # tc qdisc show dev em1 ingress
        args = ['qdisc', 'show', 'dev', dev, 'ingress']
        lines = self._as_root([], args, use_root_namespace=True)
        for line in lines.split('\n'):
            if re.search('ingress', line):
                return True
        return False

    def has_sub_ingress(self, dev):
        # command example:
        # tc filter show dev em1 parent ffff:
        args = ['filter', 'show', 'dev', dev, 'parent', 'ffff:']
        lines = self._as_root([], args, use_root_namespace=True)
        return len(lines)

    def add_root_ingress(self, dev):
        # command example:
        # tc qdisc add dev em1 ingress
        args = ['qdisc', 'add', 'dev', dev, 'ingress']
        self._as_root([], args, use_root_namespace=True)

    def remove_root_ingress(self, dev):
        # command example:
        # tc qdisc del dev em1 ingress
        args = ['qdisc', 'del', 'dev', dev, 'ingress']
        self._as_root([], args, use_root_namespace=True)

    def has_root_egress(self, dev):
        # command example:
        # tc qdisc show dev em1
        args = ['qdisc', 'show', 'dev', dev]
        lines = self._as_root([], args, use_root_namespace=True)
        for line in lines.split('\n'):
            if re.search('htb 1: root', line):
                return True
        return False

    def has_sub_egress(self, dev):
        # command example:
        # tc filter show dev em1
        args = ['filter', 'show', 'dev', dev]
        lines = self._as_root([], args, use_root_namespace=True)
        return len(lines)

    def add_root_egress(self, dev):
        # command example:
        # tc qdisc add dev em1 root handle 1: htb default 1
        args = ['qdisc', 'add', 'dev', dev, 'root']
        args += ['handle', '1:', 'htb', 'default', '1']
        self._as_root([], args, use_root_namespace=True)

    def remove_root_egress(self, dev):
        # command example:
        # tc qdisc del dev em1 root
        args = ['qdisc', 'del', 'dev', dev, 'root']
        self._as_root([], args, use_root_namespace=True)

    def list_ingress(self, dev, keyword):
        # command example:
        # tc filter show dev em1 parent ffff:
        args = ['filter', 'show', 'dev', dev, 'parent', 'ffff:']
        lines = self._as_root([], args, use_root_namespace=True)
        last_line = ''
        prios = []
        for line in lines.split('\n'):
            line = line.strip()
            if re.search(keyword, line):
                prios.append(last_line.split()[4])
            last_line = line
        return prios

    def add_ingress(self, dev, ip, rate, burst):
        # command example:
        # tc filter add dev em1 parent ffff: \
        # protocol all u32 match ip dst 172.27.35.221 \
        # police rate 40Mbit burst 40Mbit mtu 64kb drop flowid :1
        args = ['filter', 'add', 'dev', dev]
        args += ['parent', 'ffff:', 'protocol', 'all', 'u32']
        args += ['match', 'ip', 'dst', ip]
        args += ['police', 'rate', rate, 'burst', burst]
        args += ['mtu', '64kb', 'drop', 'flowid', ':1']
        self._as_root([], args, use_root_namespace=True)

    def remove_ingress(self, dev, prio):
        # command example:
        # tc filter del dev em1 parent ffff: prio 49151
        args = ['filter', 'del', 'dev', dev]
        args += ['parent', 'ffff:', 'prio', prio]
        self._as_root([], args, use_root_namespace=True)

    def list_egress(self, dev, keyword):
        # command example:
        # tc filter show dev em1
        args = ['filter', 'show', 'dev', dev]
        lines = self._as_root([], args, use_root_namespace=True)
        last_line = ''
        prios = []
        for line in lines.split('\n'):
            line = line.strip()
            if re.search(keyword, line):
                prios.append(last_line.split()[6])
            last_line = line
        return prios

    def add_egress(self, dev, ip, rate, burst):
        # command example:
        # tc filter add dev em1 parent 1:0 \
        # protocol all u32 match ip src 172.27.35.221 \
        # police rate 80Mbit burst 80Mbit mtu 64kb drop flowid :1
        args = ['filter', 'add', 'dev', dev]
        args += ['parent', '1:0', 'protocol', 'all', 'u32']
        args += ['match', 'ip', 'src', ip]
        args += ['police', 'rate', rate, 'burst', burst]
        args += ['mtu', '64kb', 'drop', 'flowid', ':1']
        self._as_root([], args, use_root_namespace=True)

    def remove_egress(self, dev, prio):
        # command example:
        # tc filter del dev em1 prio 49152
        args = ['filter', 'del', 'dev', dev, 'prio', prio]
        self._as_root([], args, use_root_namespace=True)

    def add_qos(self, ip_or_cidr, dev, meta):
        if not self.has_root_ingress(dev):
            self.add_root_ingress(dev)

        # check exist ingress
        keyword = ip_to_hex(ip_or_cidr)
        for prio in self.list_ingress(dev, keyword):
            # remove ingress
            self.remove_ingress(dev, prio)

        # add ingress
        ip = cidr_to_ip(ip_or_cidr)
        rate = meta['ingress']['rate']
        burst = meta['ingress']['burst']
        self.add_ingress(dev, ip, rate, burst)

        if not self.has_root_egress(dev):
            self.add_root_egress(dev)

        # check exist egress
        for prio in self.list_egress(dev, keyword):
            # remove egress
            self.remove_egress(dev, prio)

        # add egress
        rate = meta['egress']['rate']
        burst = meta['egress']['burst']
        self.add_egress(dev, ip, rate, burst)

    def remove_qos(self, ip_or_cidr, dev):
        keyword = ip_to_hex(ip_or_cidr)
        # check exist ingress
        for prio in self.list_ingress(dev, keyword):
            # remove ingress
            self.remove_ingress(dev, prio)

        # check exist root ingress and exist sub ingresses
        if self.has_root_ingress(dev) and not self.has_sub_ingress(dev):
            # remove root ingress
            self.remove_root_ingress(dev)

        # check exist egress
        for prio in self.list_egress(dev, keyword):
            # remove egress
            self.remove_egress(dev, prio)

        # check exist root egress and exist sub egresses
        if self.has_root_egress(dev) and not self.has_sub_egress(dev):
            # remove root egress
            self.remove_root_egress(dev)
