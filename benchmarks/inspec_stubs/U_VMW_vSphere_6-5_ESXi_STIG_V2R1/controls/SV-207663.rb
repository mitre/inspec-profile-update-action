control 'SV-207663' do
  title 'For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required.'
  desc 'When a port group is set to VLAN 4095, this activates VGT mode. In this mode, the vSwitch passes all network frames to the guest VM without modifying the VLAN tags, leaving it up to the guest to deal with them. VLAN 4095 should be used only if the guest has been specifically configured to manage VLAN tags itself. If VGT is enabled inappropriately, it might cause denial-of-service or allow a guest VM to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> Virtual switches. For each virtual switch, review the port group VLAN tags and verify they are not set to 4095.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup | Select Name, VLanID

If any port group is configured with VLAN 4095 and is not documented as a needed exception, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> Virtual switches. Highlight a port group (where VLAN ID set to 4095) and click Edit settings. Change the VLAN ID to not be 4095 and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7918r364388_chk'
  tag severity: 'medium'
  tag gid: 'V-207663'
  tag rid: 'SV-207663r388482_rule'
  tag stig_id: 'ESXI-65-000064'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7918r364389_fix'
  tag 'documentable'
  tag legacy: ['SV-104161', 'V-94075']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
