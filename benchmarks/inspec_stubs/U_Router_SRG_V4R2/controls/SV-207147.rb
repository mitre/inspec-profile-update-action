control 'SV-207147' do
  title 'The PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.'
  desc 'LDP provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE router advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE router during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'Review the router configuration to determine if LDP messages are being authenticated for the targeted LDP sessions.

If authentication is not being used for the LDP sessions using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Implement authentication for all targeted LDP sessions using a FIPS-approved message authentication code algorithm.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7408r382424_chk'
  tag severity: 'medium'
  tag gid: 'V-207147'
  tag rid: 'SV-207147r604135_rule'
  tag stig_id: 'SRG-NET-000343-RTR-000001'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-7408r382425_fix'
  tag 'documentable'
  tag legacy: ['SV-93005', 'V-78299']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
