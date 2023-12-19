control 'SV-220695' do
  title 'The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.'
  desc 'VLAN hopping can be initiated by an attacker who has access to a switch port belonging to the same VLAN as the native VLAN of the trunk link connecting to another switch that the victim is connected to. If the attacker knows the victim’s MAC address, it can forge a frame with two 802.1q tags and a layer 2 header with the destination address of the victim. Since the frame will ingress the switch from a port belonging to its native VLAN, the trunk port connecting to the victim’s switch will simply remove the outer tag because native VLAN traffic is to be untagged. The switch will forward the frame on to the trunk link unaware of the inner tag with a VLAN ID of which the victim’s switch port is a member.'
  desc 'check', 'Review the switch configurations and examine all trunk links. Verify the native VLAN has been configured to a VLAN ID other than the ID of the default VLAN (i.e. VLAN 1) as shown in the example below:

interface Ethernet0/1
switchport
switchport mode trunk
switchport trunk native vlan 44

Note: An alternative to configuring a dedicated native VLAN is to ensure that all native VLAN traffic is tagged. This will mitigate the risk of VLAN hopping since there will always be an outer tag for native traffic as it traverses an 802.1q trunk link.

If the native VLAN has the same VLAN ID as the default VLAN, this is a finding.'
  desc 'fix', 'To ensure the integrity of the trunk link and prevent unauthorized access, the ID of the native VLAN of the trunk port must be changed from the default VLAN (i.e., VLAN 1) to its own unique VLAN ID. 

SW1(config)#int e0/1
SW1(config-if)#switchport trunk native vlan 44

Note: The native VLAN ID must be the same on both ends of the trunk link; otherwise, traffic could accidentally leak between broadcast domains.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22410r539136_chk'
  tag severity: 'medium'
  tag gid: 'V-220695'
  tag rid: 'SV-220695r539671_rule'
  tag stig_id: 'CISC-L2-000260'
  tag gtitle: 'SRG-NET-000512-L2S-000012'
  tag fix_id: 'F-22399r539137_fix'
  tag 'documentable'
  tag legacy: ['SV-110365', 'V-101261']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
