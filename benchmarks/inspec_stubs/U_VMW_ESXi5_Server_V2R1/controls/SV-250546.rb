control 'SV-250546' do
  title 'Virtual switch VLANs must be fully documented and have only the required VLANs.'
  desc 'When defining a physical switch port for trunk mode, only specified VLANs must be configured on the VLAN trunk link. The risk with not fully documenting all VLANs on the vSwitch is that it is possible that a physical trunk port might be configured without needed VLANs, or with unneeded VLANs, potentially enabling an administrator to either accidentally or maliciously connect a VM to an unauthorized VLAN.'
  desc 'check', 'Both standard and distributed vSwitch configurations can be viewed in the vSphere Client. 

For vSwitch: Home>> Inventory>> Hosts and Clusters, then select an ESXi host in Inventory panel on left. In the Configuration tab, Hardware window, under Networking, select each vSwitch, and for each port group on the vSwitch, verify and record the VLAN IDs used. 

For dvSwitches, go to Home>> Inventory>> Networking and for each dvSwitch in the inventory, and for each dvPortGroup in each dvSwitch, select Edit Settings>> Policies>> VLAN and verify the recorded VLAN IDs. 

If the system VLAN IDs do not match the VLAN IDs on record, this is a finding.'
  desc 'fix', 'Both standard and distributed vSwitch configurations can be viewed in the vSphere Client. For vSwitch: Home>> Inventory>> Hosts and Clusters, then select an ESXi host in Inventory panel on left. In the Configuration tab, Hardware window, under Networking, select each vSwitch, and for each port group on the vSwitch, verify and record the VLAN IDs used. For dvSwitches, go to Home>> Inventory>> Networking and for each dvSwitch in the inventory, and for each dvPortGroup in each dvSwitch, select Edit Settings>> Policies>> VLAN and record all VLAN IDs.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53981r798635_chk'
  tag severity: 'low'
  tag gid: 'V-250546'
  tag rid: 'SV-250546r798637_rule'
  tag stig_id: 'ESXI5-VMNET-000004'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53935r798636_fix'
  tag 'documentable'
  tag legacy: ['SV-51217', 'V-39359']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
