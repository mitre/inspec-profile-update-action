control 'SV-207249' do
  title 'The VPN Gateway must use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plain text. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the product being evaluated.'
  desc 'check', 'Verify the VPN Gateway uses a FIPS-validated cryptographic module to generate cryptographic hashes.

If the VPN Gateway does not use a FIPS-validated cryptographic module to generate cryptographic hashes, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7509r378368_chk'
  tag severity: 'medium'
  tag gid: 'V-207249'
  tag rid: 'SV-207249r856722_rule'
  tag stig_id: 'SRG-NET-000510-VPN-002160'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-7509r378369_fix'
  tag 'documentable'
  tag legacy: ['V-97193', 'SV-106331']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
