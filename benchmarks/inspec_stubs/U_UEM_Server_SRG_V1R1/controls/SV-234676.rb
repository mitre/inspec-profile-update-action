control 'SV-234676' do
  title 'The UEM server must validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses. 

Satisfies:FIA_X509_EXT.1.1(1)"
  desc 'check', 'Verify the UEM server validates certificates used for TLS functions by performing RFC 5280-compliant certification path validation.

If the UEM server does not validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', 'Configure the UEM server to validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37861r616029_chk'
  tag severity: 'medium'
  tag gid: 'V-234676'
  tag rid: 'SV-234676r617355_rule'
  tag stig_id: 'SRG-APP-000605-UEM-000401'
  tag gtitle: 'SRG-APP-000605'
  tag fix_id: 'F-37826r615663_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
