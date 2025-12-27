control 'SV-250547' do
  title 'All vSwitch and VLAN IDs must be fully documented.'
  desc 'VLAN tagging used on a vSwitch must correspond to the IDs on external VLAN-aware upstream switches, if any. If VLAN IDs are not tracked completely, mistaken re-use of IDs could allow for traffic to be allowed between inappropriate physical and virtual machines. Similarly, wrong or missing VLAN IDs may lead to traffic not passing between appropriate physical and virtual machines.'
  desc 'check', 'From the vSphere Client/vCenter: Go to "Home>> Inventory>> Hosts and Clusters". Select each ESXi host with virtual switches connected to active VMs. Go to "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> [Portgroup Name]>> VLAN ID". 

Verify the recorded VLAN IDs in the (site-specific) tracking system. 

If the system VLAN IDs do not match the external VLAN IDs on record, this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter: Go to "Home>> Inventory>> Hosts and Clusters". Select each ESXi host with virtual switches connected to active VMs. Go to "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> [Portgroup Name]>> VLAN ID". Record all VLAN IDs in a (site-specific) tracking system.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53982r798638_chk'
  tag severity: 'low'
  tag gid: 'V-250547'
  tag rid: 'SV-250547r798640_rule'
  tag stig_id: 'ESXI5-VMNET-000005'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53936r798639_fix'
  tag 'documentable'
  tag legacy: ['V-39360', 'SV-51218']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
