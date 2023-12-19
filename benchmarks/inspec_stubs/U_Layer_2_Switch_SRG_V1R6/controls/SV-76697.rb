control 'SV-76697' do
  title 'The layer 2 switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is not used to access the switch for management.

If the default VLAN is being used to access the switch, this is a finding.'
  desc 'fix', 'Configure the switch for management access to use a VLAN other than the default VLAN.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-63011r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62207'
  tag rid: 'SV-76697r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000010'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-68127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
