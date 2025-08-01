control 'SV-220414' do
  title 'MarkLogic Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'Check MarkLogic configuration to verify use of NIST FIPS validated cryptographic modules to provision digital signatures.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. Click the local cluster.
3. If SSL FIPS enabled button is false, this is a finding.'
  desc 'fix', 'Configure MarkLogic to use NIST FIPS validated cryptographic modules to provision digital signatures.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. Click the local cluster.
3. Enable SSL FIPS option.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22129r863307_chk'
  tag severity: 'medium'
  tag gid: 'V-220414'
  tag rid: 'SV-220414r863309_rule'
  tag stig_id: 'ML09-00-012000'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-22118r863308_fix'
  tag 'documentable'
  tag legacy: ['SV-110185', 'V-101081']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
