control 'SV-240063' do
  title 'HAProxy must perform RFC 5280-compliant certification path validation if PKI is being used.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.'
  desc 'check', 'Interview the ISSO.

Review HAProxy configuration to verify that certificates being provided by the web server are validated, RFC 5280-compliant certificates. If PKI is not being used, this is NA. 

If certificates are not validated, RFC 5280-compliant certificates, this is a finding.'
  desc 'fix', 'Install validated RFC 5280-compliant certificates.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43296r665356_chk'
  tag severity: 'medium'
  tag gid: 'V-240063'
  tag rid: 'SV-240063r879612_rule'
  tag stig_id: 'VRAU-HA-000195'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-43255r665357_fix'
  tag 'documentable'
  tag legacy: ['SV-99813', 'V-89163']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
