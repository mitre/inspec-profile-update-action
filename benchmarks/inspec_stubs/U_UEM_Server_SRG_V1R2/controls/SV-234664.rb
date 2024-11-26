control 'SV-234664' do
  title 'The UEM server must use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard. 

The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the product being evaluated. 

Satisfies:FCS_COP.1.1(2)'
  desc 'check', 'Verify the UEM server uses a FIPS-validated cryptographic module to generate cryptographic hashes.

If the UEM server does not use a FIPS-validated cryptographic module to generate cryptographic hashes, this is a finding.'
  desc 'fix', 'Configure the UEM server to use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37849r615626_chk'
  tag severity: 'high'
  tag gid: 'V-234664'
  tag rid: 'SV-234664r879885_rule'
  tag stig_id: 'SRG-APP-000514-UEM-000389'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-37814r615627_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
