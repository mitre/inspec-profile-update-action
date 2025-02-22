control 'SV-239956' do
  title 'The Cisco ASA must be configured to use a FIPS-validated cryptographic module to implement IPsec encryption services.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plain text. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

The cryptographic module used must have one FIPS-validated encryption algorithm (i.e., validated Advanced Encryption Standard [AES]). This validated algorithm must be used for encryption for cryptographic security function within the product being evaluated.'
  desc 'check', 'Verify the ASA uses a FIPS-validated cryptographic module to implement IPsec encryption services.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp encryption aes-192

If the ASA is not configured to use a FIPS-validated cryptographic module to implement IPsec encryption services, this is a finding.'
  desc 'fix', 'Configure the ASA to use a FIPS-validated cryptographic module to implement IPsec encryption services as shown in the example below.

ASA2(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
ASA2(config-ipsec-proposal)# protocol esp encryption aes-192'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43189r666272_chk'
  tag severity: 'medium'
  tag gid: 'V-239956'
  tag rid: 'SV-239956r666274_rule'
  tag stig_id: 'CASA-VN-000200'
  tag gtitle: 'SRG-NET-000510-VPN-002170'
  tag fix_id: 'F-43148r666273_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
