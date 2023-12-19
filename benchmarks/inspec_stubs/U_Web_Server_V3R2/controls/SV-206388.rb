control 'SV-206388' do
  title 'The web server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the web server provides PKI functionality that validates certification paths in accordance with RFC 5280. If PKI is not being used, this is NA. 

If the web server is using PKI, but it does not perform this requirement, this is a finding.'
  desc 'fix', 'Configure the web server to validate certificates in accordance with RFC 5280.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6649r377756_chk'
  tag severity: 'medium'
  tag gid: 'V-206388'
  tag rid: 'SV-206388r879612_rule'
  tag stig_id: 'SRG-APP-000175-WSR-000095'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-6649r377757_fix'
  tag 'documentable'
  tag legacy: ['SV-54307', 'V-41730']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
