control 'SV-220642' do
  title 'The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.'
  desc 'In a VLAN-based network, switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with other networking devices using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP) - all untagged traffic. 

As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configurations and verify that no access switch ports have been assigned membership to the default VLAN (i.e., VLAN 1). VLAN assignments can be verified via the show vlan command:

SW1#show vlan

VLAN Name Status Ports
---- -------------------------------- --------- -------------------------------
1 default active 
10 User VLAN active Gi0/3, Gi1/0, Gi1/1, Gi1/2
 Gi1/3, Gi2/1
20 Management VLAN active Gi0/2
999 VLAN0999 active Gi2/0

If access switch ports are assigned to the default VLAN, this is a finding.'
  desc 'fix', 'Remove the assignment of the default VLAN from all access switch ports.'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22357r507972_chk'
  tag severity: 'medium'
  tag gid: 'V-220642'
  tag rid: 'SV-220642r539671_rule'
  tag stig_id: 'CISC-L2-000220'
  tag gtitle: 'SRG-NET-000512-L2S-000008'
  tag fix_id: 'F-22346r507973_fix'
  tag 'documentable'
  tag legacy: ['SV-110255', 'V-101151']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
