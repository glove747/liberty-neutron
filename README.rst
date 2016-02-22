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
