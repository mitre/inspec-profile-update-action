control 'SV-255985' do
  title 'The Arista MLS layer 2 switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.'
  desc 'VLAN hopping can be initiated by an attacker who has access to a switch port belonging to the same VLAN as the native VLAN of the trunk link connecting to another switch that the victim is connected to. If the attacker knows the victim’s MAC address, it can forge a frame with two 802.1q tags and a layer 2 header with the destination address of the victim. Since the frame will ingress the switch from a port belonging to its native VLAN, the trunk port connecting to the victim’s switch will simply remove the outer tag because native VLAN traffic is to be untagged. The switch will forward the frame on to the trunk link unaware of the inner tag with a VLAN ID of which the victim’s switch port is a member.'
  desc 'check', 'Review the Arista MLS switch configuration for all trunk ports to have a unique native VLAN ID that is not the default VLAN 1 by using the following example:

switch(config)#sh run | sec native vlan
interface Ethernet4
   description STIG Disable_VLAN 1 and native vlan to 1000
   switchport trunk native vlan 1000
   switchport trunk allowed vlan 2-4094

If the native VLAN has the same VLAN ID as the default VLAN, this is a finding.'
  desc 'fix', 'Configure the interface trunk ports for the unique Native VLAN ID and configure the VLAN allowed by using the following commands:

switch(config)#interface Ethernet10
switch(config-eth10)#description #STIG VLAN 1 Pruning
switch(config-eth10)# switchport trunk native vlan 1000
switch(config-eth10)#switchport trunk allowed vlan 2-4094'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59661r882295_chk'
  tag severity: 'medium'
  tag gid: 'V-255985'
  tag rid: 'SV-255985r882297_rule'
  tag stig_id: 'ARST-L2-000220'
  tag gtitle: 'SRG-NET-000512-L2S-000012'
  tag fix_id: 'F-59604r882296_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
