control 'SV-216791' do
  title 'The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', 'Step 1: Review the design plan for deploying L3VPN and VRF-lite. 

Step 2: Review the design plan for deploying L3VPN and VRF-lite. Review all CE-facing interfaces and verify that the proper VRF is defined via the ip vrf forwarding command. In the example below, COI1 is bound to interface GigabitEthernet0/0/0/1, while COI2 is bound to GigabitEthernet0/0/0/2.

interface GigabitEthernet0/0/0/1
description link to COI1
 vrf COI1
 ipv4 address x.1.34.12 255.255.255.252
!
interface GigabitEthernet0/0/0/2
 description link to COI2
 vrf COI2
 ipv4 address x.1.22.12 255.255.255.252

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.'
  desc 'fix', 'Configure the PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18023r288750_chk'
  tag severity: 'high'
  tag gid: 'V-216791'
  tag rid: 'SV-216791r531087_rule'
  tag stig_id: 'CISC-RT-000630'
  tag gtitle: 'SRG-NET-000512-RTR-000005'
  tag fix_id: 'F-18021r288751_fix'
  tag 'documentable'
  tag legacy: ['V-96789', 'SV-105927']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
