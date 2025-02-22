control 'SV-16743' do
  title 'The ESX Server external physical switch ports are configured to VLAN 1.'
  desc 'Physical switches use the native VLAN for switch control and management protocol. Native VLAN frames are not tagged with any VLAN ID in many types of switches. The trunk ports implicitly treat all untagged frames as native VLAN frames. VLAN 1 is the default native VLAN ID for many commercial switches. However, in many enterprise networks, the native VLAN might be VLAN 1 or any number depending on the switch type. ESX Server does not support virtual switch port groups configured to VLAN 1. If the physical switch port that the ESX Server is connected to is configured with VLAN 1, the ESX Server will drop all packets. The ESX Server virtual switch port groups will be configured with any value between 2 and 4094. Utilizing VLAN 1 will cause a denial of service since the ESX Server drops this traffic.'
  desc 'check', 'Work with the network reviewer and system administrator to determine compliance. Go to the switch that connects the ESX Server to the network. Request a copy of the switch configuration to verify the ports that the ESX Server plugs into are not configured to VLAN 1. Below is an example of disabling VLAN 1 and creating a VLAN that may be used for ESX Server traffic.

Cisco IOS Example: 

Interface VLAN1
no ip address
shutdown

interface VLAN 12
ip address 10.0.0.25 255.255.255.0
no shutdown

set interface sc0 10.0.0.25 255.255.255.0'
  desc 'fix', 'Configure ESX Server external physical switches to something other than VLAN 1.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16022r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15804'
  tag rid: 'SV-16743r1_rule'
  tag stig_id: 'ESX0150'
  tag gtitle: 'External physical switch ports are set to VLAN 1.'
  tag fix_id: 'F-15747r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
