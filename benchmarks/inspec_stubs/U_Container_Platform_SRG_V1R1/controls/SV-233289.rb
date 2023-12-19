control 'SV-233289' do
  title 'The container platform must use a FIPS-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality.'
  desc 'Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

Cryptographic module used must have one FIPS-validated encryption algorithm (i.e., validated Advanced Encryption Standard [AES]). This validated algorithm must be used for encryption for cryptographic security function within the container platform component and information residing in the container platform registry and keystore.'
  desc 'check', 'Review the container platform configuration to ensure FIPS-validated cryptographic modules are implemented to encrypt unclassified information requiring confidentiality. 

If FIPS-validated cryptographic modules are not being used, this is a finding.'
  desc 'fix', 'Configure the container platform to use FIPS-validated cryptographic modules to encrypt unclassified information requiring confidentiality.'
  impact 0.7
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36225r599503_chk'
  tag severity: 'high'
  tag gid: 'V-233289'
  tag rid: 'SV-233289r599509_rule'
  tag stig_id: 'SRG-APP-000635-CTR-001405'
  tag gtitle: 'SRG-APP-000635'
  tag fix_id: 'F-36193r599504_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
