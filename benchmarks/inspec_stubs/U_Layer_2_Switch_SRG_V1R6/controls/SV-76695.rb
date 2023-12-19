control 'SV-76695' do
  title 'The layer 2 switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. With larger campus networks, care needs to be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, thereby influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is pruned from trunk links that do not require it.

If the default VLAN is not pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.'
  desc 'fix', 'Best practice for VLAN-based networks is to prune unnecessary trunk links from gaining access to the default VLAN and to ensure that frames belonging to the default VLAN do not traverse trunks not requiring frames from the VLAN.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-63009r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62205'
  tag rid: 'SV-76695r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000009'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-68125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
