control 'SV-80567' do
  title 'The HP FlexFabric Switch must implement Rapid STP where VLANs span multiple switches with redundant links.'
  desc 'Spanning Tree Protocol (STP) is implemented on bridges and switches to prevent layer 2 loops when a broadcast domain spans multiple bridges and switches and when redundant links are provisioned to provide high availability in case of link failures. Convergence time can be significantly reduced using Rapid STP (802.1w) instead of STP (802.1d), resulting in improved availability. Rapid STP should be deployed by implementing either Rapid  or Multiple Spanning-Tree Protocol (MSTP) -- the latter scales much better when there are many VLANs.'
  desc 'check', 'In cases where VLANs do not span multiple switches, it is a best practice to not implement STP. Avoiding the use of STP will provide the most deterministic and highly available network topology.  If STP is required, then review the HP FlexFabric Switch configuration to verify that Rapid STP has been implemented. 

If Rapid STP has not been implemented where STP is required, this is a finding.

[HP]display stp vlan X'
  desc 'fix', 'Configure Rapid STP to be implemented at the access and distribution layers where VLANs span multiple switches.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66077'
  tag rid: 'SV-80567r1_rule'
  tag stig_id: 'HFFS-L2-000020'
  tag gtitle: 'SRG-NET-000512-L2S-000003'
  tag fix_id: 'F-72153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
