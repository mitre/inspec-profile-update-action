control 'SV-216840' do
  title 'The vCenter Server for Windows must configure all port groups to a value other than that of the native VLAN.'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up as belonging to native VLAN of the physical switch. For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged). If the ESXi virtual switch port group uses the native VLAN ID, traffic from those VMs will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies. 

Review the port group VLAN tags and verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies. Click "Edit" and under the VLAN section change the VLAN ID to a non-native VLAN and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18071r366234_chk'
  tag severity: 'medium'
  tag gid: 'V-216840'
  tag rid: 'SV-216840r612237_rule'
  tag stig_id: 'VCWN-65-000018'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18069r366235_fix'
  tag 'documentable'
  tag legacy: ['SV-104577', 'V-94747']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
