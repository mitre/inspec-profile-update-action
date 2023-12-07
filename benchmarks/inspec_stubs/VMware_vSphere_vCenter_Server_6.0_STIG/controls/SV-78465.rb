control 'SV-78465' do
  title 'All port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required.'
  desc 'When a port group is set to VLAN 4095, this activates VGT mode. In this mode, the vSwitch passes all network frames to the guest VM without modifying the VLAN tags, leaving it up to the guest to deal with them. VLAN 4095 should be used only if the guest has been specifically configured to manage VLAN tags itself. If VGT is enabled inappropriately, it might cause denial-of-service or allow a guest VM to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Review the port group VLAN tags and verify they are not set to 4095.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with VLAN 4095 and is not documented as a needed exception, this is a finding.'
  desc 'fix', 'To change the VLAN ID of distributed virtual port groups do the following:

From the vSphere Web Client go to Networking >> Select a distributed port group >> Manage >> Settings >> Policies.  Click Edit and under the VLAN section change the VLAN ID to not be 4095 and click OK.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63975'
  tag rid: 'SV-78465r1_rule'
  tag stig_id: 'VCWN-06-000019'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69905r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
