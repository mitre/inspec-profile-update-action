control 'SV-80845' do
  title 'Multi-Protocol Labeled Switching (MPLS) labels must not be exchanged between the enclaves edge routers and any external neighbor routers.'
  desc 'MPLS label exchange via Label Distribution Protocol (LDP) or Resource Reservation Protocol (RSVP) with any external neighbor creates the risk of label spoofing that could disrupt optimum routing, or even drop packets that are encapsulated with a label that is not in the MPLS forwarding table.'
  desc 'check', 'Review the DISN-facing interfaces of the enclave perimeter  routers to verify that LDP or RSVP is not enabled.

If any of these interfaces are LDP or RSVP enabled, this is a finding.'
  desc 'fix', 'Disable LDP and RSVP on DISN-facing interfaces on all perimeter routers.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66355'
  tag rid: 'SV-80845r1_rule'
  tag stig_id: 'NET2001'
  tag gtitle: 'NET2001'
  tag fix_id: 'F-72431r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
