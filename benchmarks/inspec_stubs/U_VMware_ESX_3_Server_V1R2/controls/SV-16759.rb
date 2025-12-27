control 'SV-16759' do
  title 'External physical switch ports configured for EST mode are configured with spanning-tree enabled.'
  desc 'EST mode has a one-to-one relationship, the number of VLANs supported on the ESX Server system is limited to the number of physical network adapter ports assigned to the VMkernel. EST is enabled when the port group’s VLAN ID is set to 0 or left blank. Due to the integration of the ESX Server into the physical network, the physical network adapters will need to have spanning-tree disabled or portfast configured for external switches, since VMware virtual switches do not support STP.  If these are not set, potential performance and connectivity issues could arise. Virtual switch uplinks do not create loops within the physical switch network.'
  desc 'check', 'Request a copy of the external switch configuration that the ESX Server is connected to. Work with the network reviewer and system administrator to review the configuration to ensure that either spanning-tree is disabled for those ports or spanning-tree is configured to portfast. If either one of these conditions is not configured, this is a finding.  

Cisco IOS panning-tree portfast:
Switch# show running-config interface <gigabit or fastethernet> <module/port number>
Interface gigabit 5/1
No ip address
Switchport
Switchport access vlan <number>
Switchport mode access
Spanning-tree portfast
End
Switch#

Cisco IOS spanning-tree disabled:
Switch# show running config
….
No spanning-tree vlan <number>
….

Should see the VLAN number in the no spanning-tree vlan command.'
  desc 'fix', 'Disable spanning-tree or configure spanning-tree to portfast for the external switch ports.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16130r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15820'
  tag rid: 'SV-16759r1_rule'
  tag stig_id: 'ESX0290'
  tag gtitle: 'Spanning-tree set for switch ports in EST mode.'
  tag fix_id: 'F-15772r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
