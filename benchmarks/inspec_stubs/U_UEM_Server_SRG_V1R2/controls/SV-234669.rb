control 'SV-234669' do
  title 'The UEM server must be configured to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation, either on DoD-only or on public-facing servers. 

Satisfies:FCS_TLSC_EXT.1.1 
Reference:PP-MDM-412061'
  desc 'check', 'Verify the UEM server is configured to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.

If the UEM server is not configured to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0, this is a finding.'
  desc 'fix', 'Configure the UEM server to prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37854r615641_chk'
  tag severity: 'medium'
  tag gid: 'V-234669'
  tag rid: 'SV-234669r879889_rule'
  tag stig_id: 'SRG-APP-000560-UEM-000394'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-37819r615642_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
