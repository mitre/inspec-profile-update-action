control 'SV-77785' do
  title 'All port groups must be configured to a value other than that of the native VLAN.'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up as belonging to native VLAN of the physical switch. For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged). If the ESXi virtual switch port group uses the native VLAN ID, traffic from those VMs will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking.  Review the port group VLAN tags and verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup | Select Name, VLanId

If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking >> Select properties on the virtual switch >> Select the port group and click Edit.  Change the VLAN ID to a non-native VLAN and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64029r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63295'
  tag rid: 'SV-77785r1_rule'
  tag stig_id: 'ESXI-06-000063'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
