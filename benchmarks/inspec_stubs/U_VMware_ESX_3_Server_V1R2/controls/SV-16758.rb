control 'SV-16758' do
  title 'Promiscuous mode is enabled for virtual switches during the ESX Server boot process.'
  desc 'ESX Server has the ability to run virtual and physical network adapters in promiscuous mode. Promiscuous mode may be enabled on public and private virtual switches. When promiscuous mode is enabled for a public virtual switch, all virtual machines connected to the public virtual switch have the potential of reading all packets sent across that network, from other virtual machines and any physical machines or other network devices. When promiscuous mode is enabled for a private virtual switch, all virtual machines connected to the private virtual switch have the potential of reading all packets across that network, meaning only the virtual machines connected to that private virtual switch. By default, promiscuous mode is set to Reject, meaning that the virtual network adapter cannot operate in Promiscuous mode.  

Promiscuous mode will be disabled on the ESX Server virtual switches since confidential data may be revealed while in this mode. Promiscuous mode is disabled by default on the ESX Server; however there might be a legitimate reason to enable it for debugging, monitoring, or troubleshooting reasons.  To enable promiscuous mode for a virtual switch, a value is inserted into a special virtual file in the /proc file system. After a reboot of the ESX Server, promiscuous mode will be disabled again since the value is in the /proc directory. One way to ensure promiscuous mode is enabled indefinitely is to add a command to the /etc/rc.local boot script in the service console.'
  desc 'check', 'On the ESX service console, perform the following:

# less /etc/rc.local
#!/bin/sh
# 
# This script will be executed *after* all other init scripts.
#  You can put your own initialization entries in here if you don’t 
# want to do the full Sys V style init stuff.
Touch /var/lock/subsys/local

If you see something similar to the following, this is a finding:

echo “PromiscuousAllowed yes” > /proc/vmware/net/vmnic0/config

Note: If promiscuous mode is turned on for troubleshooting purposes, it must be documented and approved with the IAO/SA.'
  desc 'fix', 'Disable promiscuous mode during the ESX Server boot process.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16109r1_chk'
  tag severity: 'high'
  tag gid: 'V-15819'
  tag rid: 'SV-16758r1_rule'
  tag stig_id: 'ESX0280'
  tag gtitle: 'Promiscuous mode is set for virtual switches.'
  tag fix_id: 'F-15771r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
