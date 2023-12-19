control 'SV-207263' do
  title 'The VPN Gateway must validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Verify the VPN Gateway validates TLS certificates by performing RFC 5280-compliant certification path validation.

If the VPN Gateway does not validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7523r378410_chk'
  tag severity: 'medium'
  tag gid: 'V-207263'
  tag rid: 'SV-207263r608988_rule'
  tag stig_id: 'SRG-NET-000580-VPN-002410'
  tag gtitle: 'SRG-NET-000580'
  tag fix_id: 'F-7523r378411_fix'
  tag 'documentable'
  tag legacy: ['SV-106359', 'V-97221']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
