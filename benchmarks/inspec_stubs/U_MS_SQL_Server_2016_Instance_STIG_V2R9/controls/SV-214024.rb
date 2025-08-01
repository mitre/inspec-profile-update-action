control 'SV-214024' do
  title 'SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
 
It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards. 
 
For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'Review the server documentation, if this system does not contain data that must be encrypted, this finding is NA.

Verify that Windows is configured to require the use of FIPS compliant algorithms for the unclassified information that requires it.

Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing."

If  "System Cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" is not enabled, this is a finding.'
  desc 'fix', 'Configure Windows to require the use of FIPS compliant algorithms for the unclassified information that requires it. 
 
Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing." >> Change the Setting option to "Enabled" >> Restart Windows'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15241r863343_chk'
  tag severity: 'medium'
  tag gid: 'V-214024'
  tag rid: 'SV-214024r879885_rule'
  tag stig_id: 'SQL6-D0-015800'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-15239r313856_fix'
  tag 'documentable'
  tag legacy: ['SV-94015', 'V-79309']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
