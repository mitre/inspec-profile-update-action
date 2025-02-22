control 'SV-237038' do
  title 'The A10 Networks ADC when used for TLS encryption and decryption must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

The A10 Networks ADC can be configured to use Open Certificate Status Protocol (OCSP) and/or certificate revocation lists (CRLs) to verify the revocation status of certificates. OCSP is preferred since it reduces the overhead associated with CRLs."
  desc 'check', 'If the ALG does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS), this is not applicable.

Verify the ALG validates certificates used for TLS functions by performing RFC 5280-compliant certification path validation.

If the ALG does not validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', 'If intermediary services for TLS are provided, configure the device to validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.

The following command configures an authentication-server profile for an Online Certificate Status Protocol (OCSP) server:
authentication-server ocsp [profile-name]'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40257r639559_chk'
  tag severity: 'medium'
  tag gid: 'V-237038'
  tag rid: 'SV-237038r639561_rule'
  tag stig_id: 'AADC-AG-000042'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-40220r639560_fix'
  tag 'documentable'
  tag legacy: ['SV-82459', 'V-67969']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
