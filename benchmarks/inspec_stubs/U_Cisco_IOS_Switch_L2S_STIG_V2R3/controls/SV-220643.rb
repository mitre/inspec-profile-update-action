control 'SV-220643' do
  title 'The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. 

With larger campus networks, care must be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is pruned from trunk links that do not require it:

SW1#show interfaces trunk

Port Mode Encapsulation Status Native vlan
Gi0/1 on 802.1q trunking 1
Gi0/2 on 802.1q trunking 1

Port Vlans allowed on trunk
Gi0/1 1-998,1000-4094
Gi0/2 1-4094

If the default VLAN is not pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.'
  desc 'fix', 'Prune VLAN 1 from any trunk links as necessary:

SW1(config)#int g0/2
SW1(config-if)#switchport trunk allowed vlan except 1

Verify that VLAN 1 is not allowed on the trunk link:

SW1#show interfaces trunk

Port Mode Encapsulation Status Native vlan
Gi0/1 on 802.1q trunking 1
Gi0/2 on 802.1q trunking 1

Port Vlans allowed on trunk
Gi0/1 1-998,1000-4094
Gi0/2 2-4094'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22358r507975_chk'
  tag severity: 'medium'
  tag gid: 'V-220643'
  tag rid: 'SV-220643r539671_rule'
  tag stig_id: 'CISC-L2-000230'
  tag gtitle: 'SRG-NET-000512-L2S-000009'
  tag fix_id: 'F-22347r507976_fix'
  tag 'documentable'
  tag legacy: ['SV-110257', 'V-101153']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
