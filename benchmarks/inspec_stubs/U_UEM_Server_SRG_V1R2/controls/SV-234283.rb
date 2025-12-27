control 'SV-234283' do
  title 'The UEM server must use TLS 1.2, or higher, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DoD-only or on public-facing servers. 

Satisfies:FCS_TLSC_EXT.1.1 
Reference:PP-MDM-412061'
  desc 'check', 'Verify the UEM server uses TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.

If the UEM server does not use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access, this is a finding.'
  desc 'fix', 'Configure the UEM server to use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37468r613859_chk'
  tag severity: 'medium'
  tag gid: 'V-234283'
  tag rid: 'SV-234283r879519_rule'
  tag stig_id: 'SRG-APP-000014-UEM-000009'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37433r613860_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
