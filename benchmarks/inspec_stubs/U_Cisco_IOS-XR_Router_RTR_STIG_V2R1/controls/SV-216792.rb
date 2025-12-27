control 'SV-216792' do
  title 'The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).'
  desc 'The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is traffic separation. Each interface can only be associated to one VRF, which is the fundamental framework for traffic separation. Forwarding decisions are made based on the routing table belonging to the VRF. Control of what routes are imported into or exported from a VRF is based on the RT. It is critical that traffic does not leak from one COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured for each VRF.'
  desc 'check', 'Review the design plan for MPLS/L3VPN and VRF-lite to determine what RTs have been assigned for each VRF.  Review the router configuration and verify that the correct RT is configured for each VRF. In the example below, route target 13:13 has been configured for COI1.

vrf COI1
 address-family ipv4 unicast
  import route-target
   13:13
  !
  export route-target
   13:13
  !
 !
!

If there are VRFs configured with the wrong RT, this is a finding.'
  desc 'fix', 'Configure the router to have each VRF instance defined with the correct RT.

RP/0/0/CPU0:R3(config)#vrf COI1
RP/0/0/CPU0:R3(config-vrf)#address-family ipv4 unicast 
RP/0/0/CPU0:R3(config-vrf-af)#import route-target 13:13
RP/0/0/CPU0:R3(config-vrf-af)#export route-target 13:13
RP/0/0/CPU0:R3(config-vrf-af)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18024r288753_chk'
  tag severity: 'high'
  tag gid: 'V-216792'
  tag rid: 'SV-216792r531087_rule'
  tag stig_id: 'CISC-RT-000640'
  tag gtitle: 'SRG-NET-000512-RTR-000006'
  tag fix_id: 'F-18022r288754_fix'
  tag 'documentable'
  tag legacy: ['V-96791', 'SV-105929']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
