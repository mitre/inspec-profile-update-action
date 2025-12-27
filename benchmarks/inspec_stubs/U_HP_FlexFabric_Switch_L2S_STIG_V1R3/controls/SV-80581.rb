control 'SV-80581' do
  title 'The HP FlexFabric Switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the HP FlexFabric Switch configuration and verify that the default VLAN is not used to access the switch for management.

If the default VLAN is being used to access the HP FlexFabric Switch, this is a finding.

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
  desc 'fix', 'Configure the HP FlexFabric Switch for management access to use a VLAN other than the default VLAN.

interface Vlan-interface xxxx
 description MGMT VLAN
 ip address xxx.xxx.xxx.xxx <mask>'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66091'
  tag rid: 'SV-80581r1_rule'
  tag stig_id: 'HFFS-L2-000027'
  tag gtitle: 'SRG-NET-000512-L2S-000010'
  tag fix_id: 'F-72167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
