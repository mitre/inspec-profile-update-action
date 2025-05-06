control 'SV-206668' do
  title 'The layer 2 switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. With larger campus networks, care needs to be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, thereby influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is pruned from trunk links that do not require it.

If the default VLAN is not pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.'
  desc 'fix', 'Best practice for VLAN-based networks is to prune unnecessary trunk links from gaining access to the default VLAN and to ensure that frames belonging to the default VLAN do not traverse trunks not requiring frames from the VLAN.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6926r298434_chk'
  tag severity: 'medium'
  tag gid: 'V-206668'
  tag rid: 'SV-206668r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000009'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6926r298435_fix'
  tag 'documentable'
  tag legacy: ['SV-76695', 'V-62205']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
