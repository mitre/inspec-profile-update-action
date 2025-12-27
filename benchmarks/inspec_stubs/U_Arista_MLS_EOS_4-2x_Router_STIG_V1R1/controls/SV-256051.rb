control 'SV-256051' do
  title 'The MPLS router must be configured to have TTL propagation disabled.'
  desc "The head end of the label-routered path (LSP), the label edge router (LER) will decrement the IP packet's time-to-live (TTL) value by one and then copy the value to the MPLS TTL field. At each label-routered router (LSR) hop, the MPLS TTL value is decremented by one. The MPLS router that pops the label (either the penultimate LSR or the egress LER) will copy the packet's MPLS TTL value to the IP TTL field and decrement it by one.

This TTL propagation is the default behavior. Because the MPLS TTL is propagated from the IP TTL, a traceroute will list every hop in the path, be it routed or label routered, thereby exposing core nodes. With TTL propagation disabled, LER decrements the IP packet's TTL value by one and then places a value of 255 in the packet's MPLS TTL field, which is then decremented by one as the packet passes through each LSR in the MPLS core. Because the MPLS TTL never drops to zero, none of the LSP hops triggers an ICMP TTL exceeded message and consequently, these hops are not recorded in a traceroute. Hence, nodes within the MPLS core cannot be discovered by an attacker."
  desc 'check', 'Review the Arista router configuration to verify TTL propagation is disabled.

Verify the router is configured to disable the TTL propagation.

no mpls icmp ttl-exceeded tunneling

If the Arista router is not configured to disable TTL propagation, this is a finding.'
  desc 'fix', 'Configure Arista LERs to disable TTL propagation.

Configure the router to disable the TTL propagation in MPLS core network.

router(config)#no mpls icmp ttl-exceeded tunneling'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59727r882493_chk'
  tag severity: 'medium'
  tag gid: 'V-256051'
  tag rid: 'SV-256051r882495_rule'
  tag stig_id: 'ARST-RT-000720'
  tag gtitle: 'SRG-NET-000512-RTR-000004'
  tag fix_id: 'F-59670r882494_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
