利用tc给floatingIP限速  
配置如下：  
/etc/neutron/rootwrap.d 增加 tc.filters

# neutron-rootwrap command filters for nodes on which neutron is  
# expected to control network  
#  
# This file should be owned by (and only-writeable by) the root user  
  
# format seems to be  
# cmd-name: filter-name, raw-command, user, args  
  
[Filters]  
  
# tc  
tc: CommandFilter, tc, root  

在/etc/neutron/neutron.conf添加:  
fip_qos_ingress_max_kbps = 1024  
fip_qos_ingress_max_burst_kbps = 2048  
fip_qos_egress_max_kbps = 1024  
fip_qos_egress_max_burst_kbps = 2048

在/etc/neutron/l3_agent.ini中添加： 
external_network_interface=eth1  
其中Eth1标示br-ex所对应的网卡  
