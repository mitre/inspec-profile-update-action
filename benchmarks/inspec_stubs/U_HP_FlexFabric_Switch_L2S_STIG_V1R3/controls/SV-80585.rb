control 'SV-80585' do
  title 'The HP FlexFabric Switch must have the native VLAN assigned to a VLAN ID other than the default VLAN ID for all 802.1q trunk links.'
  desc 'VLAN hopping can be initiated by an attacker who has access to a switch port belonging to the same VLAN as the native VLAN of the trunk link connecting to another switch that the victim is connected to. If the attacker knows the victim’s MAC address, it can forge a frame with two 802.1q tags and a layer 2 header with the destination address of the victim. Since the frame will ingress the switch from a port belonging to its native VLAN, the trunk port connecting to the victim’s switch will simply remove the outer tag because native VLAN traffic is to be untagged. The switch will forward the frame on to the trunk link unaware of the inner tag with a VLAN ID of which the victim’s  switch port is a member.'
  desc 'check', 'Review the HP FlexFabric Switch configurations and examine all trunk links. Verify the native VLAN has been configured to a VLAN ID other than the default VLAN 1. Connect to switch via console or SSH.

<HP> display current interface Bridge-Aggregation 
#
interface Bridge-Aggregation1
 description To-DistroEast(10G)
 port link-type trunk
 undo port trunk permit vlan 1
 port trunk permit vlan 2100 to 2102 4017
 port trunk pvid vlan 4017
 link-aggregation mode dynamic

If any of the trunk links are assigned to VLAN 1, this is a finding.'
  desc 'fix', 'Configure the ID of the native vlan on all trunk port(s).

[HP-GigabitEthernet1/0/13] undo port trunk permit vlan 1
[HP-GigabitEthernet1/0/13]port trunk pvid vlan 4017'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66095'
  tag rid: 'SV-80585r1_rule'
  tag stig_id: 'HFFS-L2-000029'
  tag gtitle: 'SRG-NET-000512-L2S-000012'
  tag fix_id: 'F-72171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
