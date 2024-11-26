control 'SV-78463' do
  title 'All port groups must be configured to a value other than that of the native VLAN.'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up as belonging to native VLAN of the physical switch. For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged). If the ESXi virtual switch port group uses the native VLAN ID, traffic from those VMs will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Review the port group VLAN tags and verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Click Edit and under the VLAN section change the VLAN ID to a non-native VLAN and click OK.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64725r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63973'
  tag rid: 'SV-78463r1_rule'
  tag stig_id: 'VCWN-06-000018'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
