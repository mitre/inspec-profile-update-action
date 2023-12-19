control 'SV-206640' do
  title 'The DBMS must implement NIST FIPS 140-2 validated cryptographic modules to generate and validate cryptographic hashes.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If the DBMS does not employ NIST FIPS 140-2 validated cryptographic modules to generate and verify cryptographic hashes, this is a finding.'
  desc 'fix', 'Implement a NIST FIPS 140-2 validated cryptographic module in the DBMS for generation and verification of cryptographic hashes.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6900r291588_chk'
  tag severity: 'medium'
  tag gid: 'V-206640'
  tag rid: 'SV-206640r617447_rule'
  tag stig_id: 'SRG-APP-000514-DB-000382'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-6900r291589_fix'
  tag 'documentable'
  tag legacy: ['SV-72591', 'V-58161']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
