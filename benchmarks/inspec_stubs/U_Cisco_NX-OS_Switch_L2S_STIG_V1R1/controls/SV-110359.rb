control 'SV-110359' do
  title 'The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. With larger campus networks, care needs to be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, thereby influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is pruned from trunk links that do not require it.

SW1# show interface trunk

--------------------------------------------------------------------------------
Port Native Status Port
 Vlan Channel
--------------------------------------------------------------------------------
Eth1/1 1 trunking --
Eth1/2 1 trunking --

--------------------------------------------------------------------------------
Port Vlans Allowed on Trunk
--------------------------------------------------------------------------------
Eth1/1 1-998,1000-4094
Eth1/2 1-998,1000-4094

If the default VLAN is not pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.'
  desc 'fix', 'Step 1: Prune VLAN 1 from any trunk links as necessary.

SW1(config)# int e1/2
SW1(config-if)# switchport trunk allowed vlan except 1, 999
SW1(config-if)# end

Step 2: Verify VLAN 1 is not allowed on the trunk link.

SW1# show interface trunk

--------------------------------------------------------------------------------
Port Native Status Port
 Vlan Channel
--------------------------------------------------------------------------------
Eth1/1 1 trunking --
Eth1/2 1 trunking --

--------------------------------------------------------------------------------
Port Vlans Allowed on Trunk
--------------------------------------------------------------------------------
Eth1/1 1-998,1000-4094
Eth1/2 2-998,1000-4094'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101255'
  tag rid: 'SV-110359r1_rule'
  tag stig_id: 'CISC-L2-000230'
  tag gtitle: 'SRG-NET-000512-L2S-000009'
  tag fix_id: 'F-106959r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
