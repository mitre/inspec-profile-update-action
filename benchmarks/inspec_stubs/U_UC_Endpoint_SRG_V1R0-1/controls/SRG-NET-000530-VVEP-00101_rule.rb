control 'SRG-NET-000530-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint must prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DOD-only or public-facing servers.'
  desc 'check', 'Verify the Unified Communications Endpoint prohibits client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, and SSL 3.0.

If the Unified Communications Endpoint does not prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, and SSL 3.0, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000530-VVEP-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000530-VVEP-00101'
  tag rid: 'SRG-NET-000530-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000530-VVEP-00101'
  tag gtitle: 'SRG-NET-000530-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000530-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
