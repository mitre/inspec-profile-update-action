control 'SV-80579' do
  title 'The HP FlexFabric Switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. With larger campus networks, care needs to be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, thereby influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the HP FlexFabric Switch configuration and verify that the default VLAN is pruned from trunk links that do not require it.

If the default VLAN is not pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.

<HP>display vlan 1

 VLAN ID: 1
 VLAN type: Static
 Route interface: Configured
 Description: VLAN 0001
 Name: VLAN 0001
 Tagged ports:   None
 Untagged ports:
    GigabitEthernet1/0/1          GigabitEthernet1/0/2
    GigabitEthernet1/0/3          GigabitEthernet1/0/4
    GigabitEthernet1/0/5          GigabitEthernet1/0/6
    GigabitEthernet1/0/7          GigabitEthernet1/0/8'
  desc 'fix', 'Remove the native vlan from trunks that do not require it.

[HP-interface GigabitEthernet1/0/1] undo port trunk permit vlan 1'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66089'
  tag rid: 'SV-80579r1_rule'
  tag stig_id: 'HFFS-L2-000026'
  tag gtitle: 'SRG-NET-000512-L2S-000009'
  tag fix_id: 'F-72165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
