control 'SV-221117' do
  title 'The Cisco PE switch must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', 'Step 1: Review the design plan for deploying MPLS/L3VPN. 

Step 2: Review all CE-facing interfaces and verify that the proper VRF is defined via the ip vrf forwarding command. In the example below, customer 1 is bound to interface Ethernet2/1, while customer 2 is bound to Ethernet2/2.

interface Ethernet2/1
 no switchport
 vrf member CUST1
 ip address x.2.22.3/24

interface Ethernet2/2
 no switchport
 vrf member CUST2
 ip address x.2.8.4/24

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.'
  desc 'fix', 'Configure the PE switch to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22832r409840_chk'
  tag severity: 'high'
  tag gid: 'V-221117'
  tag rid: 'SV-221117r622190_rule'
  tag stig_id: 'CISC-RT-000630'
  tag gtitle: 'SRG-NET-000512-RTR-000005'
  tag fix_id: 'F-22821r409841_fix'
  tag 'documentable'
  tag legacy: ['SV-111053', 'V-101949']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
