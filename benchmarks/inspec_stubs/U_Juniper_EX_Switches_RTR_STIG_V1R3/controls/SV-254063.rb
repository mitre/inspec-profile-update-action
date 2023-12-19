control 'SV-254063' do
  title 'The Juniper MPLS router must be configured to have TTL Propagation disabled.'
  desc "The head end of the label-switched path (LSP), the label edge router (LER) will decrement the IP packet's time-to-live (TTL) value by one and then copy the value to the MPLS TTL field. At each label-switched router (LSR) hop, the MPLS TTL value is decremented by one. The MPLS router that pops the label (either the penultimate LSR or the egress LER) will copy the packet's MPLS TTL value to the IP TTL field and decrement it by one.

This TTL propagation is the default behavior. Because the MPLS TTL is propagated from the IP TTL, a traceroute will list every hop in the path, be it routed or label switched, thereby exposing core nodes. With TTL propagation disabled, LER decrements the IP packet's TTL value by one and then places a value of 255 in the packet's MPLS TTL field, which is then decremented by one as the packet passes through each LSR in the MPLS core. Because the MPLS TTL never drops to zero, none of the LSP hops triggers an ICMP TTL exceeded message and consequently, these hops are not recorded in a traceroute. Hence, nodes within the MPLS core cannot be discovered by an attacker."
  desc 'check', 'Review the router configuration to verify that TTL propagation is disabled.
[edit protocols mpls]
no-propagate-ttl;

If the router is not configured to disable TTL propagation, this is a finding.'
  desc 'fix', 'Configure LERs to disable TTL propagation.

set protocols mpls no-propagate-ttl'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57515r844220_chk'
  tag severity: 'medium'
  tag gid: 'V-254063'
  tag rid: 'SV-254063r844222_rule'
  tag stig_id: 'JUEX-RT-000910'
  tag gtitle: 'SRG-NET-000512-RTR-000004'
  tag fix_id: 'F-57466r844221_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
