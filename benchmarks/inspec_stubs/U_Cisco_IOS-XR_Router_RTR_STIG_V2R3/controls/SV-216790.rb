control 'SV-216790' do
  title 'The Cisco MPLS router must be configured to have TTL Propagation disabled.'
  desc "The head end of the label-switched path (LSP), the label edge router (LER) will decrement the IP packet's time-to-live (TTL) value by one and then copy the value to the MPLS TTL field. At each label-switched router (LSR) hop, the MPLS TTL value is decremented by one. The MPLS router that pops the label (either the penultimate LSR or the egress LER) will copy the packet's MPLS TTL value to the IP TTL field and decrement it by one.

This TTL propagation is the default behavior. Because the MPLS TTL is propagated from the IP TTL, a traceroute will list every hop in the path, be it routed or label switched, thereby exposing core nodes. With TTL propagation disabled, LER decrements the IP packet's TTL value by one and then places a value of 255 in the packet's MPLS TTL field, which is then decremented by one as the packet passes through each LSR in the MPLS core. Because the MPLS TTL never drops to zero, none of the LSP hops triggers an ICMP TTL exceeded message and consequently, these hops are not recorded in a traceroute. Hence, nodes within the MPLS core cannot be discovered by an attacker."
  desc 'check', 'Review the router configuration to verify that TTL propagation is disabled as shown in the example below.

mpls ip-ttl-propagate disable

If the MPLS router is not configured to disable TTL propagation, this is a finding.'
  desc 'fix', 'Configure the MPLS router to disable TTL propagation as shown in the example below.

RP/0/0/CPU0:R3(config)#mpls ip-ttl-propagate disable'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18022r288747_chk'
  tag severity: 'medium'
  tag gid: 'V-216790'
  tag rid: 'SV-216790r531087_rule'
  tag stig_id: 'CISC-RT-000620'
  tag gtitle: 'SRG-NET-000512-RTR-000004'
  tag fix_id: 'F-18020r288748_fix'
  tag 'documentable'
  tag legacy: ['SV-105925', 'V-96787']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
