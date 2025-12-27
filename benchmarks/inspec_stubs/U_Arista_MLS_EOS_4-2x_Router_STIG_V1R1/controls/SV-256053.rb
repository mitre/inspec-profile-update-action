control 'SV-256053' do
  title 'The PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).'
  desc 'The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is traffic separation. Each interface can only be associated to one VRF, which is the fundamental framework for traffic separation. Forwarding decisions are made based on the routing table belonging to the VRF. Control of what routes are imported into or exported from a VRF is based on the RT. It is critical that traffic does not leak from one COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured for each VRF.'
  desc 'check', 'Verify the correct RT is configured for each VRF.

Review the design plan for MPLS/L3VPN and VRF-lite to determine what RTs have been assigned for each VRF.

Review the route-target import, route-target, or route-target export statements under each configured VRF and verify the correct RTs have been defined for each VRF.

To verify the correct RTs have been defined for each VRF on a PE router, execute the command "sh run sec router bgp".

router bgp 65000
   vrf PROD
      rd 200:200
      route-target import vpn-ipv4 200:200
      route-target export vpn-ipv4 200:200

Note: Import and export route-maps are normally used when finer granularity is required.

If VRFs are configured with the wrong RT, this is a finding.'
  desc 'fix', "Configure all J-PE Arista routers to have the correct VRF defined with the appropriate RT.

Configure the route-target's for import and export.

PE11(config)#router bgp 65000
PE11(config-router-bgp)#vrf PROD
PE11(config-router-bgp-vrf-PROD)#rd 200:200
PE11(config-router-bgp-vrf-PROD)#route-target import vpn-ipv4 200:200
PE11(config-router-bgp-vrf-PROD)#route-target export vpn-ipv4 200:200"
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59729r882499_chk'
  tag severity: 'high'
  tag gid: 'V-256053'
  tag rid: 'SV-256053r882501_rule'
  tag stig_id: 'ARST-RT-000740'
  tag gtitle: 'SRG-NET-000512-RTR-000006'
  tag fix_id: 'F-59672r882500_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
