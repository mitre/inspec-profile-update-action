control 'SV-77787' do
  title 'All port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required.'
  desc 'When a port group is set to VLAN 4095, this activates VGT mode. In this mode, the vSwitch passes all network frames to the guest VM without modifying the VLAN tags, leaving it up to the guest to deal with them. VLAN 4095 should be used only if the guest has been specifically configured to manage VLAN tags itself. If VGT is enabled inappropriately, it might cause denial-of-service or allow a guest VM to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking.  Review the port group VLAN tags and verify they are not set 4095.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup | Select Name, VLanID

If any port group is configured with VLAN 4095 and is not documented as a needed exception, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Networking >> Select properties on the virtual switch >> Select the port group and click Edit.  Change the VLAN ID to not be 4095 and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64031r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63297'
  tag rid: 'SV-77787r1_rule'
  tag stig_id: 'ESXI-06-000064'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
