control 'SV-221041' do
  title 'The Cisco PE switch providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.'
  desc 'VPWS is an L2VPN technology that provides a virtual circuit between two PE switches to forward Layer 2 frames between two customer-edge switches or switches through an MPLS-enabled IP core. The ingress PE switch (virtual circuit head-end) encapsulates Ethernet frames inside MPLS packets using label stacking and forwards them across the MPLS network to the egress PE switch (virtual circuit tail-end). During a virtual circuit setup, the PE switches exchange VC label bindings for the specified VC ID. The VC ID specifies a pseudowire associated with an ingress and egress PE switch and the customer-facing attachment circuits. 

To guarantee that all frames are forwarded onto the correct pseudowire and to the correct customer and attachment circuits, it is imperative that the correct VC ID is configured for each attachment circuit.'
  desc 'check', 'Verify that the correct and unique VCID has been configured for the appropriate attachment circuit. In the example below, GigabitEthernet0/1 is the CE-facing interface that is configured for VPWS with the VCID of 55.

interface GigabitEthernet0/1
 xconnect x.2.2.12 55 encapsulation mpls

If the correct VC ID has not been configured on both switches, this is a finding.'
  desc 'fix', 'Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID.'
  impact 0.7
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22756r408917_chk'
  tag severity: 'high'
  tag gid: 'V-221041'
  tag rid: 'SV-221041r622190_rule'
  tag stig_id: 'CISC-RT-000670'
  tag gtitle: 'SRG-NET-000512-RTR-000008'
  tag fix_id: 'F-22745r408918_fix'
  tag 'documentable'
  tag legacy: ['SV-110903', 'V-101799']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
