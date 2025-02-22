control 'SV-233271' do
  title 'The container platform must use a valid FIPS 140-2 approved cryptographic modules to generate hashes.'
  desc 'The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the container platform components being evaluated.

FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.'
  desc 'check', 'Review the container platform configuration to validate that valid FIPS 140-2 approved cryptographic modules are being used to generate hashes. 

If non-valid or unapproved FIPS 140-2 cryptographic modules are being used to generate hashes, this is a finding.'
  desc 'fix', 'Configure the container platform to use valid FIPS 140-2 approved cryptographic modules to generate hashes.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36207r599729_chk'
  tag severity: 'medium'
  tag gid: 'V-233271'
  tag rid: 'SV-233271r599729_rule'
  tag stig_id: 'SRG-APP-000514-CTR-001315'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-36175r599450_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
