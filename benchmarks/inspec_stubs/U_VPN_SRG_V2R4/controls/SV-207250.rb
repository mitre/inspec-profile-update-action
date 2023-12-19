control 'SV-207250' do
  title 'The VPN Gateway must use a FIPS-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plain text. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

The cryptographic module used must have one FIPS-validated encryption algorithm (i.e., validated Advanced Encryption Standard [AES]). This validated algorithm must be used for encryption for cryptographic security function within the product being evaluated.'
  desc 'check', 'Verify the VPN Gateway uses a FIPS-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality.

If the VPN Gateway does not use a FIPS-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use a FIPS-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7510r378371_chk'
  tag severity: 'medium'
  tag gid: 'V-207250'
  tag rid: 'SV-207250r608988_rule'
  tag stig_id: 'SRG-NET-000510-VPN-002170'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-7510r378372_fix'
  tag 'documentable'
  tag legacy: ['V-97195', 'SV-106333']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
