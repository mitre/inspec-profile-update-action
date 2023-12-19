control 'SV-207176' do
  title 'The PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', 'Review the design plan for deploying L3VPN and VRF-lite. 

Review all CE-facing interfaces and verify that the proper VRF is defined.

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.'
  desc 'fix', 'Configure the PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7437r382616_chk'
  tag severity: 'high'
  tag gid: 'V-207176'
  tag rid: 'SV-207176r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000005'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7437r382617_fix'
  tag 'documentable'
  tag legacy: ['V-78293', 'SV-92999']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
