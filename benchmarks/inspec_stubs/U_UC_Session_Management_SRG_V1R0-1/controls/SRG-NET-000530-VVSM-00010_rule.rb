control 'SRG-NET-000530-VVSM-00010_rule' do
  title 'The Unified Communications Session Manager must be configured to use only TLS 1.2 or greater for all TLS and SSL communications.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DOD-only or public-facing servers.'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to only use TLS 1.2 or greater for all TLS and SSL communications.

If the Voice Video Session is not configured to only use TLS 1.2 or greater for all TLS and SSL communications, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to only use TLS 1.2 or greater for all TLS and SSL communications.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000530-VVSM-00010_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000530-VVSM-00010'
  tag rid: 'SRG-NET-000530-VVSM-00010_rule'
  tag stig_id: 'SRG-NET-000530-VVSM-00010'
  tag gtitle: 'SRG-NET-000530-VVSM-00010'
  tag fix_id: 'F-SRG-NET-000530-VVSM-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
