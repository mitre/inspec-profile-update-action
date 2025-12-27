control 'SV-214022' do
  title 'SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
 
For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'Verify that Windows is configured to require the use of FIPS compliant algorithms. 
 
Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing." 
 
If the Security Setting for this option is "Disabled" this is a finding.'
  desc 'fix', 'In Windows, open Administrative Tools >> Local Security Policy. 

Expand Local Policies >> Security Options. 

In the right-side pane, double-click on "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing."'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15239r313849_chk'
  tag severity: 'high'
  tag gid: 'V-214022'
  tag rid: 'SV-214022r879885_rule'
  tag stig_id: 'SQL6-D0-015600'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-15237r313850_fix'
  tag 'documentable'
  tag legacy: ['SV-94011', 'V-79305']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
