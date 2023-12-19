control 'SV-206641' do
  title 'The DBMS must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If the DBMS contains or is intended to contain unclassified information requiring confidentiality and cryptographic protection, and does not employ NIST FIPS 140-2 or 140-3 validated cryptographic modules to provide this protection, this is a finding.'
  desc 'fix', 'Implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provide cryptographic protection for the unclassified information that requires it.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6901r836868_chk'
  tag severity: 'medium'
  tag gid: 'V-206641'
  tag rid: 'SV-206641r836870_rule'
  tag stig_id: 'SRG-APP-000514-DB-000383'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-6901r836869_fix'
  tag 'documentable'
  tag legacy: ['SV-72593', 'V-58163']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
