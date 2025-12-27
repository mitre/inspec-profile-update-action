control 'SV-239955' do
  title 'The Cisco ASA must be configured to use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  desc 'FIPS 140-2/140-3 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plain text. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2/140-3 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2/140-3 standard.

The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the product being evaluated.'
  desc 'check', 'Verify the ASA is configured to use a FIPS-validated cryptographic module to generate cryptographic hashes.

Step 1: Verify that a FIPS-validated hash is used for IKE Phase 1 as shown in the example below.
 
crypto ikev2 policy 1
…
…
…
 integrity sha384

Step 2: Verify that a FIPS-validated hash is used for the IPsec SA.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp integrity sha-384

If the ASA is not configured to use a FIPS-validated cryptographic module to generate cryptographic hashes, this is a finding.'
  desc 'fix', 'Configure the ASA to use a FIPS-validated cryptographic module to generate cryptographic hashes as shown in the examples below.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# integrity sha384
ASA1(config-ikev2-policy)# exit

ASA1(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
ASA1(config-ipsec-proposal)# protocol esp integrity sha-384
ASA1(config-ipsec-proposal)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43188r916123_chk'
  tag severity: 'medium'
  tag gid: 'V-239955'
  tag rid: 'SV-239955r916125_rule'
  tag stig_id: 'CASA-VN-000190'
  tag gtitle: 'SRG-NET-000510-VPN-002160'
  tag fix_id: 'F-43147r916124_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
