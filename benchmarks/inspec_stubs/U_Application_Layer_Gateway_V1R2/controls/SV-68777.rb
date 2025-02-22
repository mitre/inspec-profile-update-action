control 'SV-68777' do
  title 'The ALG that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'If the ALG does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS), this is not applicable.

Verify the ALG validates certificates used for TLS functions by performing RFC 5280-compliant certification path validation.

If the ALG does not validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', 'If intermediary services for TLS are provided, configure the ALG to validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55147r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54531'
  tag rid: 'SV-68777r1_rule'
  tag stig_id: 'SRG-NET-000164-ALG-000100'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-59385r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
