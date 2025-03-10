control 'SV-80851' do
  title 'Rapid Spanning Tree Protocol (STP) must be implemented at the access and distribution layers where Virtual Local Area Networks (VLANs) span multiple switches.'
  desc 'Spanning Tree Protocol (STP) is implemented on bridges and switches to prevent Layer 2 loops when a broadcast domain spans multiple bridges and switches and when redundant links are provisioned to provide high availability in case of link failures. Convergence time can be significantly reduced using Rapid STP (802.1w) instead of STP (802.1d), resulting in improved availability. Rapid STP should be deployed by implementing either Rapid Per-VLAN-Spanning-Tree (Rapid-PVST) or Multiple Spanning-Tree Protocol (MSTP), the later scales much better when there are many VLANs.'
  desc 'check', 'In cases where VLANs do not span multiple switches it is a best practice to not implement STP. Avoiding the use of STP will provide the most deterministic and highly available network topology.  If STP is required, then review the switch configuration to verify that RSTP or MSTP has been implemented. Following are example configurations:

RSTP

spanning-tree mode rapid-pvst

MST

spanning-tree mode mst
spanning-tree mst configuration
 name Region1
 revision 1
 instance 1 vlan 10, 11, 12
 instance 2 vlan 13, 14

If RSTP or MSTP has not been implemented where STP is required, this is a finding.

Note: Note: Cisco has implemented RSTP as part of MSTP and Rapid-PVST+.'
  desc 'fix', 'Configure Rapid STP be implemented at the access and distribution layers where VLANs span multiple switches.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67007r1_chk'
  tag severity: 'low'
  tag gid: 'V-66361'
  tag rid: 'SV-80851r1_rule'
  tag stig_id: 'NET2004'
  tag gtitle: 'NET2004'
  tag fix_id: 'F-72437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
