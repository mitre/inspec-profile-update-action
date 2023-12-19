control 'SV-255977' do
  title 'The Arista MLS layer 2 Arista MLS switch must implement Rapid STP where VLANs span multiple switches with redundant links.'
  desc 'Spanning Tree Protocol (STP) is implemented on bridges and switches to prevent layer 2 loops when a broadcast domain spans multiple bridges and switches and when redundant links are provisioned to provide high availability in case of link failures. Convergence time can be significantly reduced using Multiple Spanning-Tree (802.1s) instead of Rapid STP (802.1w) instead of STP (802.1d), resulting in improved availability. Multiple Spanning-Tree Protocol (MSTP) should be deployed by implementing either Rapid Per-VLAN-Spanning-Tree (Rapid-PVST) or Multiple Spanning-Tree MST, the latter scales topologies much better when there are many VLANs.'
  desc 'check', 'In cases where VLANs do not span multiple switches, it is a best practice to not implement STP. Avoiding the use of STP will provide the most deterministic and highly available network topology. If STP is required, review the Arista MLS switch configuration to verify that Rapid STP has been implemented.

switch(config)#sh run | sec spanning-tree
spanning-tree mode rstp
!

Note: MSTP can be configured as an alternate mode. MSTP uses RSTP for rapid convergence and enables multiple VLANs to be grouped into and mapped to the same spanning-tree instance, thereby reducing the number of spanning-tree instances needed to support a large number of VLANs.

If MSTP or Rapid STP has not been implemented where STP is required, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch for Multiple Spanning-tree (MST) or Rapid STP to be implemented at the access and distribution layers where VLANs span multiple switches.

switch(config)#spanning-tree mode mstp

The Arista MLS switch can alternatively be configured for spanning-tree mode RSTP to support a spanning-tree instance for each VLAN:

switch(config)#
spanning-tree mode rstp
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59653r882271_chk'
  tag severity: 'medium'
  tag gid: 'V-255977'
  tag rid: 'SV-255977r882273_rule'
  tag stig_id: 'ARST-L2-000140'
  tag gtitle: 'SRG-NET-000512-L2S-000003'
  tag fix_id: 'F-59596r882272_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
