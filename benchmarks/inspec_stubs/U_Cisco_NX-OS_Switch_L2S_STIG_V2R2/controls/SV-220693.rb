control 'SV-220693' do
  title 'The Cisco switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is not used to access the switch for management.

interface Vlan1

interface Vlan44
 description Management VLAN
 ip address 10.1.12.1/24

If the default VLAN is being used for management access to the switch, this is a finding.'
  desc 'fix', 'Configure the switch for management access to use a VLAN other than the default VLAN.

SW1(config)# interface vlan 44
SW1(config-if)# ip add 10.1.12.1/24
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22408r539130_chk'
  tag severity: 'medium'
  tag gid: 'V-220693'
  tag rid: 'SV-220693r539671_rule'
  tag stig_id: 'CISC-L2-000240'
  tag gtitle: 'SRG-NET-000512-L2S-000010'
  tag fix_id: 'F-22397r539131_fix'
  tag 'documentable'
  tag legacy: ['SV-110361', 'V-101257']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
