control 'SV-255979' do
  title 'The Arista MLS layer 2 switch must have all trunk links enabled statically.'
  desc 'When trunk negotiation is enabled via Dynamic Trunk Protocol (DTP), considerable time can be spent negotiating trunk settings (802.1q or ISL) when a node or interface is restored. While this negotiation is happening, traffic is dropped because the link is up from a layer 2 perspective. Packet loss can be eliminated by setting the interface statically to trunk mode, thereby avoiding dynamic trunk protocol negotiation and significantly reducing any outage when restoring a failed link or switch.'
  desc 'check', "Review the Arista MLS switch configuration to verify that all Ethernet interfaces designated as trunk links are statically configured to specify only member tagged VLAN traffic is allowed and all nonmember VLAN traffic will be dropped unless untagged traffic is associated with the interface's native VLAN.

switch#show run | section trunk
!
interface Ethernet6
   description STIG Static Trunk
   speed forced 10000full
   switchport trunk native vlan 2102
   switchport trunk allowed vlan 2100-2102
   switchport mode trunk
!

If trunk negotiation is enabled on any interface, this is a finding."
  desc 'fix', 'Configure static Ethernet interfaces for switchport trunk mode. Ensure required VLAN member tagged traffic is allowed and all other VLAN traffic will be dropped unless an associated untagged native VLAN for the Ethernet interface is allowed.

switch#configure
switch(config)#interface Ethernet6
   description STIG Static Trunk
   speed forced 10000full
   switchport trunk native vlan 2102
   switchport trunk allowed vlan 2100-2102
   switchport mode trunk
!
switch(config)#interface Ethernet7
   description STIG Static Trunk
   speed forced 10000full
   switchport trunk native vlan 3102
   switchport trunk allowed vlan 3100-3102
   switchport mode trunk
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59655r882277_chk'
  tag severity: 'medium'
  tag gid: 'V-255979'
  tag rid: 'SV-255979r882279_rule'
  tag stig_id: 'ARST-L2-000160'
  tag gtitle: 'SRG-NET-000512-L2S-000005'
  tag fix_id: 'F-59598r882278_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
