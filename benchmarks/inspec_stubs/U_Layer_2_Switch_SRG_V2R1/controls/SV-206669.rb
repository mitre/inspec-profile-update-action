control 'SV-206669' do
  title 'The layer 2 switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is not used to access the switch for management.

If the default VLAN is being used to access the switch, this is a finding.'
  desc 'fix', 'Configure the switch for management access to use a VLAN other than the default VLAN.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6927r298437_chk'
  tag severity: 'medium'
  tag gid: 'V-206669'
  tag rid: 'SV-206669r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000010'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6927r298438_fix'
  tag 'documentable'
  tag legacy: ['SV-76697', 'V-62207']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
