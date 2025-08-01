control 'SV-204754' do
  title 'The application server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA).  Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.  Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path.  Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Review the application server documentation and deployed configuration to determine whether the application server provides PKI functionality that validates certification paths in accordance with RFC 5280.

If PKI is not being used, this is NA.

If the application server is using PKI, but it does not perform this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to validate certificates in accordance with RFC 5280.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4874r282909_chk'
  tag severity: 'medium'
  tag gid: 'V-204754'
  tag rid: 'SV-204754r879612_rule'
  tag stig_id: 'SRG-APP-000175-AS-000124'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-4874r282910_fix'
  tag 'documentable'
  tag legacy: ['SV-46609', 'V-35322']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
