control 'SV-206667' do
  title 'The layer 2 switch must not have the default VLAN assigned to any host-facing switch ports.'
  desc 'In a VLAN-based network, switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with other networking devices using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configurations and verify that no access switch ports have been assigned membership to the default VLAN (i.e., VLAN 1).  A good method of ensuring there is not membership to the default VLAN is to have it disabled (i.e., shutdown) on the switch. This technique does not prevent switch control plane protocols such as CDP, DTP, VTP, and PAgP from using the default VLAN.

If there are access switch ports assigned to the default VLAN, this is a finding.'
  desc 'fix', 'Remove the assignment of the default VLAN from all access switch ports.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6925r298431_chk'
  tag severity: 'medium'
  tag gid: 'V-206667'
  tag rid: 'SV-206667r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000008'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6925r298432_fix'
  tag 'documentable'
  tag legacy: ['SV-76693', 'V-62203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
