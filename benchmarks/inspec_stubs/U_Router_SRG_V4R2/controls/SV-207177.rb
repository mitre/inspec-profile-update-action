control 'SV-207177' do
  title 'The PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).'
  desc 'The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is traffic separation. Each interface can only be associated to one VRF, which is the fundamental framework for traffic separation. Forwarding decisions are made based on the routing table belonging to the VRF. Control of what routes are imported into or exported from a VRF is based on the RT. It is critical that traffic does not leak from one COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured for each VRF.'
  desc 'check', 'Verify that the correct RT is configured for each VRF.

Review the design plan for MPLS/L3VPN and VRF-lite to determine what RTs have been assigned for each VRF.

Review the route-target import, route-target, or route-target export statements under each configured VRF and verify that the correct RTs have been defined for each VRF. 

Note: Import and export route-maps are normally used when finer granularity is required.

If there are VRFs configured with the wrong RT, this is a finding.'
  desc 'fix', 'Configure all J-PE routers to have the correct VRF defined with the appropriate RT.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7438r382619_chk'
  tag severity: 'high'
  tag gid: 'V-207177'
  tag rid: 'SV-207177r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000006'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7438r382620_fix'
  tag 'documentable'
  tag legacy: ['V-78295', 'SV-93001']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
