control 'SV-110357' do
  title 'The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.'
  desc 'In a VLAN-based network, switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with other networking devices using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the switch configurations and verify that no access switch ports have been assigned membership to the default VLAN (i.e., VLAN 1). VLAN assignments can be verified via the show vlan command. In the example below, interfaces 1/1 and 1/2 are trunk links.

SW1# show vlan

VLAN Name Status Ports
---- -------------------------------- --------- -------------------------------
1 default active Eth1/1, Eth1/2
10 VLAN0010 active Eth1/1, Eth1/2, Eth1/3, Eth1/4
 Eth1/5, Eth1/6, Eth1/7, Eth1/8
 Eth1/9, Eth1/10, Eth1/11
 Eth1/12, Eth1/13, Eth1/14
 Eth1/15, Eth1/16, Eth1/17
 Eth1/18, Eth1/19, Eth1/20
 Eth1/21, Eth1/22, Eth1/23
 Eth1/24, Eth1/25, Eth1/26
 Eth1/27, Eth1/28, Eth1/29
 Eth1/30
11 VLAN0011 active Eth1/1, Eth1/2, Eth1/31
 Eth1/32, Eth1/33, Eth1/34
 Eth1/35, Eth1/36, Eth1/37
 Eth1/38, Eth1/39, Eth1/40 

If there are access switch ports assigned to the default VLAN, this is a finding.'
  desc 'fix', 'Remove the assignment of the default VLAN from all access switch ports.'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101253'
  tag rid: 'SV-110357r1_rule'
  tag stig_id: 'CISC-L2-000220'
  tag gtitle: 'SRG-NET-000512-L2S-000008'
  tag fix_id: 'F-106957r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
