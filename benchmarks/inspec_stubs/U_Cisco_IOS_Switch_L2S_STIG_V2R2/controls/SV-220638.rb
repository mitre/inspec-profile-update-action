control 'SV-220638' do
  title 'The Cisco switch must implement Rapid Spanning Tree Protocol (STP) where VLANs span multiple switches with redundant links.'
  desc 'STP is implemented on bridges and switches to prevent Layer 2 loops when a broadcast domain spans multiple bridges and switches and when redundant links are provisioned to provide high availability in case of link failures. 

Convergence time can be significantly reduced using Rapid STP (802.1w) instead of STP (802.1d), resulting in improved availability. Rapid STP should be deployed by implementing either Rapid Per-VLAN-Spanning-Tree (Rapid-PVST) or Multiple Spanning-Tree Protocol (MSTP). The latter scales much better when there are many VLANs.'
  desc 'check', 'In cases where VLANs do not span multiple switches, it is a best practice to not implement STP. Avoiding the use of STP will provide the most deterministic and highly available network topology. If STP is required, review the switch configuration to verify that Rapid STP has been implemented: 

hostname SW2
…
…
…
spanning-tree mode rapid-pvst

Note: MSTP can be configured as an alternate mode. MSTP uses RSTP for rapid convergence and enables multiple VLANs to be grouped into and mapped to the same spanning-tree instance, thereby reducing the number of spanning-tree instances needed to support a large number of VLANs.

If either RSTP or MSTP has not been implemented where STP is required, this is a finding.'
  desc 'fix', 'Configure Rapid STP or MSTP to be implemented at the access and distribution layers where VLANs span multiple switches as shown in the examples below:

SW2(config)#spanning-tree mode rapid-pvst

or 

SW1(config)#spanning-tree mode mst'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22353r507960_chk'
  tag severity: 'medium'
  tag gid: 'V-220638'
  tag rid: 'SV-220638r539671_rule'
  tag stig_id: 'CISC-L2-000180'
  tag gtitle: 'SRG-NET-000512-L2S-000003'
  tag fix_id: 'F-22342r507961_fix'
  tag 'documentable'
  tag legacy: ['SV-110247', 'V-101143']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
