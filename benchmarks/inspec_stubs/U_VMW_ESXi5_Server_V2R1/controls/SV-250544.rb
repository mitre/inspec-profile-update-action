control 'SV-250544' do
  title 'All dvSwitch Private VLAN IDs must be fully documented.'
  desc 'dvSwitch Private VLANs (PVLANs) require primary and secondary VLAN IDs. The IDs must correspond to the IDs on external PVLAN-aware upstream switches, if any. If VLAN IDs are not tracked completely, mistaken re-use of IDs could allow for traffic to be allowed between inappropriate physical and virtual machines. Similarly, wrong or missing PVLAN IDs may lead to traffic not passing between appropriate physical and virtual machines.'
  desc 'check', 'Verify by using the vSphere Client to connect to the vCenter Server and as administrator go to "Home>> Inventory>> Hosts and Clusters". 

Select each ESXi host with virtual switches connected to active VMs requiring securing. 

Go to "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> [Portgroup Name]>> VLAN ID". 

The dvSwitch Private VLAN tags must be documented to match the IDs on external PVLAN-aware upstream switches. Verify that Private VLAN IDs are documented and matched in an (organization-specific) tracking system. 

If any PVLAN IDs do not correspond to the IDs on external PVLAN-aware upstream switches, this is a finding.'
  desc 'fix', 'From the vSphere Client connect to the vCenter Server and as administrator go to "Home>> Inventory>> Hosts and Clusters". Select each ESXi host with virtual switches connected to active VMs requiring securing. Go to "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> [Portgroup Name]>> VLAN ID". Record all configured VLAN IDs in an organization defined tracking system.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53979r798629_chk'
  tag severity: 'low'
  tag gid: 'V-250544'
  tag rid: 'SV-250544r798631_rule'
  tag stig_id: 'ESXI5-VMNET-000002'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53933r798630_fix'
  tag 'documentable'
  tag legacy: ['SV-51215', 'V-39357']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
