control 'SV-206510' do
  title 'The Central Log Server must implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and/or to protect unclassified information requiring confidentiality and cryptographic protection.'
  desc 'FIPS 140-2 precludes the use of unvalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and/or to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

If the Central Log Server is not configured to implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and/or to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and/or to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  impact 0.7
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6770r285771_chk'
  tag severity: 'high'
  tag gid: 'V-206510'
  tag rid: 'SV-206510r400876_rule'
  tag stig_id: 'SRG-APP-000514-AU-002890'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-6770r285772_fix'
  tag 'documentable'
  tag legacy: ['SV-96017', 'V-81303']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
