control 'SV-220644' do
  title 'The Cisco switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP) - all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is not used to access the switch for management:

interface Vlan22
 description Management VLAN
 ip address 10.1.22.3 255.255.255.0

If the default VLAN is being used for management access to the switch, this is a finding.'
  desc 'fix', 'Configure the switch for management access to use a VLAN other than the default VLAN:

SW1(config)#int vlan 22
SW1(config-if)#ip add 10.1.22.3 255.255.255.0
SW1(config-if)#no shut'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22359r507978_chk'
  tag severity: 'medium'
  tag gid: 'V-220644'
  tag rid: 'SV-220644r539671_rule'
  tag stig_id: 'CISC-L2-000240'
  tag gtitle: 'SRG-NET-000512-L2S-000010'
  tag fix_id: 'F-22348r507979_fix'
  tag 'documentable'
  tag legacy: ['SV-110259', 'V-101155']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
