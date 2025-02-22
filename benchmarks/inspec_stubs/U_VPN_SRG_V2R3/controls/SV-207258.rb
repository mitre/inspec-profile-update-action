control 'SV-207258' do
  title 'The TLS VPN Gateway that supports Government-only services must prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DoD-only or public-facing servers.'
  desc 'check', 'Verify the TLS VPN Gateway that supports Government-only services prohibits client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.

If the TLS VPN Gateway that supports Government-only services does not prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0, this is a finding.'
  desc 'fix', 'Configure the TLS VPN Gateway that supports Government-only services to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7518r378395_chk'
  tag severity: 'medium'
  tag gid: 'V-207258'
  tag rid: 'SV-207258r608988_rule'
  tag stig_id: 'SRG-NET-000530-VPN-002340'
  tag gtitle: 'SRG-NET-000530'
  tag fix_id: 'F-7518r378396_fix'
  tag 'documentable'
  tag legacy: ['SV-106349', 'V-97211']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
