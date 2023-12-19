control 'SV-220415' do
  title 'MarkLogic Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'Check MarkLogic configuration to verify use of a NIST FIPS validated cryptographic modules to generate and verify cryptographic hashes.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level-privileges.

1. Click the Clusters icon.
2. Click the local cluster.
3. If SSL FIPS enabled button is false, this is a finding.'
  desc 'fix', 'Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

Configure MarkLogic to use a NIST FIPS validated cryptographic module for generation and verification of cryptographic hashes.

1. Click the Clusters icon.
2. Click the local cluster.
3. Enable SSL FIPS option.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22130r863310_chk'
  tag severity: 'medium'
  tag gid: 'V-220415'
  tag rid: 'SV-220415r863312_rule'
  tag stig_id: 'ML09-00-012100'
  tag gtitle: 'SRG-APP-000514-DB-000382'
  tag fix_id: 'F-22119r863311_fix'
  tag 'documentable'
  tag legacy: ['SV-110177', 'V-101073']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
