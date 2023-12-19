control 'SV-233284' do
  title 'The container platform must validate certificates used for Transport Layer Security (TLS) functions by performing an RFC 5280-compliant certification path validation.'
  desc 'A certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate and discourages the use of self-signed certificates.

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses. Compliance checks should be in accordance to RFC 5280.

Not adhering to RFC 5280 could result in rogue certificates, session hijacks, man-in-the-middle, denial-of-service attacks, malware, and data or information manipulation.'
  desc 'check', 'Review the container platform configuration to verify the container platform is validating certificates used for Transport Layer Security (TLS) functions by performing a RFC 5280-compliant certification path validation and that self-signed certificates are not being used. 

If the container platform is not validating certificates used for TLS functions by performing an RFC 5280-compliant certification path validation, this is a finding. 

If self-signed certificates are in use, this is a finding.'
  desc 'fix', 'Configure the container platform to validate certificates used for Transport Layer Security (TLS) functions by performing an RFC 5280-compliant certification path validation and to disable the use of self-signed certificates.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36220r601855_chk'
  tag severity: 'medium'
  tag gid: 'V-233284'
  tag rid: 'SV-233284r879897_rule'
  tag stig_id: 'SRG-APP-000605-CTR-001380'
  tag gtitle: 'SRG-APP-000605'
  tag fix_id: 'F-36188r601340_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
