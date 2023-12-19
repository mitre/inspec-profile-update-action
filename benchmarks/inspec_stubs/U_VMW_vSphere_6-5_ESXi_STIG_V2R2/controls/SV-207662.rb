control 'SV-207662' do
  title 'For the ESXi host all port groups must be configured to a value other than that of the native VLAN.'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up as belonging to native VLAN of the physical switch. For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged). If the ESXi virtual switch port group uses the native VLAN ID, traffic from those VMs will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> Virtual switches. For each virtual switch, review the port group VLAN tags and verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup | Select Name, VLanId

If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> Virtual switches. Highlight a port group (where VLAN ID set to native VLAN ID) and click Edit settings. Change the VLAN ID to a non-native VLAN and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7917r364385_chk'
  tag severity: 'medium'
  tag gid: 'V-207662'
  tag rid: 'SV-207662r388482_rule'
  tag stig_id: 'ESXI-65-000063'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7917r364386_fix'
  tag 'documentable'
  tag legacy: ['SV-104159', 'V-94073']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
