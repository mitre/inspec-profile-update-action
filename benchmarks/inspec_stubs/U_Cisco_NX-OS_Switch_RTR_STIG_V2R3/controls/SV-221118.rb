control 'SV-221118' do
  title 'The Cisco PE switch must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).'
  desc 'The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is traffic separation. Each interface can only be associated to one VRF, which is the fundamental framework for traffic separation. Forwarding decisions are made based on the routing table belonging to the VRF. Control of what routes are imported into or exported from a VRF is based on the RT. It is critical that traffic does not leak from one COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured for each VRF.'
  desc 'check', 'Review the design plan for MPLS/L3VPN to determine what RTs have been assigned for each VRF. Review the switch configuration and verify that the correct RT is configured for each VRF. In the example below, route target 13:13 has been configured for customer 1.

vrf context CUST1
 address-family ipv4 unicast
 route-target export 13:13
 route-target import 13:13

If there are VRFs configured with the wrong RT, this is a finding.'
  desc 'fix', 'Configure the switch to have each VRF instance defined with the correct RT.

SW1(config)# vrf context CUST1
SW1(config-vrf)# address-family ipv4 unicast 
SW1(config-vrf-af-ipv4)# route-target import 13:13
SW1(config-vrf-af-ipv4)# route-target export 13:13
SW1(config-vrf-af-ipv4)# end'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22833r409843_chk'
  tag severity: 'high'
  tag gid: 'V-221118'
  tag rid: 'SV-221118r622190_rule'
  tag stig_id: 'CISC-RT-000640'
  tag gtitle: 'SRG-NET-000512-RTR-000006'
  tag fix_id: 'F-22822r409844_fix'
  tag 'documentable'
  tag legacy: ['SV-111055', 'V-101951']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
