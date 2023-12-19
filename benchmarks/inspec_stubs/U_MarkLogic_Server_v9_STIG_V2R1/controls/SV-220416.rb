control 'SV-220416' do
  title 'MarkLogic Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the requirements of the data owner.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If the database contains, or is intended to contain, unclassified information requiring confidentiality and cryptographic protection, check MarkLogic configuration to verify use of NIST FIPS validated cryptographic modules to provide this protection.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. Click the local cluster.
3. If SSL FIPS enabled button is false, this is a finding.'
  desc 'fix', 'Configure MarkLogic to use NIST FIPS validated cryptographic modules to provide cryptographic protection for the unclassified information that requires it.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. Click the local cluster.
3. Enable SSL FIPS option.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22131r863313_chk'
  tag severity: 'medium'
  tag gid: 'V-220416'
  tag rid: 'SV-220416r863315_rule'
  tag stig_id: 'ML09-00-012200'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-22120r863314_fix'
  tag 'documentable'
  tag legacy: ['SV-110179', 'V-101075']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
