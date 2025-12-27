control 'SV-80577' do
  title 'The HP FlexFabric Switch must not have the default VLAN assigned to any host-facing switch ports.'
  desc 'In a VLAN-based network, switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with other networking devices using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the HP FlexFabric Switch configurations and verify that no access switch ports have been assigned membership to the default VLAN (i.e., VLAN 1).  A good method of ensuring there is not membership to the default VLAN is to have it disabled (i.e., shutdown) on the switch.

If there are access switch ports assigned to the default VLAN, this is a finding.

<HP>display vlan 1
 VLAN ID: 1
 VLAN type: Static
 Route interface: Configured:
 Description: VLAN 0001
 Name: VLAN 0001
 Tagged ports:   None
 Untagged ports:
    GigabitEthernet1/0/1          GigabitEthernet1/0/2
    GigabitEthernet1/0/3          GigabitEthernet1/0/4

[HP-GigabitEthernet1/0/12]shutdown'
  desc 'fix', 'Remove the assignment of the default VLAN from all access switch ports.

<HP>display vlan 1

[HP-vlan2]port GigabitEthernet 1/0/1 to GigabitEthernet 1/0/48

[HP-GigabitEthernet1/0/1]shutdown'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66087'
  tag rid: 'SV-80577r1_rule'
  tag stig_id: 'HFFS-L2-000025'
  tag gtitle: 'SRG-NET-000512-L2S-000008'
  tag fix_id: 'F-72163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
