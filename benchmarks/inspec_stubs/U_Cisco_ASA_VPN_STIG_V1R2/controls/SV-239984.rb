control 'SV-239984' do
  title 'The Cisco ASA VPN remote access server must be configured to validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Verify the ASA validates TLS certificates by performing RFC 5280-compliant certification path validation.

Review the ASA configuration to determine if a CA trust point has been configured as shown in the example below.

crypto ca trustpoint CA_X
 enrollment …
 validation-usage ipsec-client
 validation-usage ssl-client

If the ASA does not validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', 'Configure the ASA to validate certificates used for TLS functions by performing RFC 5280- compliant certification path validation as shown in the example below.

ASA2(config)# crypto ca trustpoint CA_X
ASA2(config-ca-trustpoint)# validation-usage ssl-client 
ASA2(config-ca-trustpoint)# validation-usage ipsec-client'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43217r666356_chk'
  tag severity: 'medium'
  tag gid: 'V-239984'
  tag rid: 'SV-239984r666358_rule'
  tag stig_id: 'CASA-VN-000730'
  tag gtitle: 'SRG-NET-000580-VPN-002410'
  tag fix_id: 'F-43176r666357_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
