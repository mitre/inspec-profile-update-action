control 'SV-89987' do
  title 'The Adobe Acrobat Pro XI Welcome Screen must be disabled.'
  desc 'The Adobe Welcome screen can be distracting. It provides marketing material and also has online links to the Adobe quick tips website, tutorials, blogs, and community forums.

When the Adobe Welcome screen is disabled, the Welcome screen will not be populated on application startup.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

If the value for bShowWelcomeScreen is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75091r1_chk'
  tag severity: 'low'
  tag gid: 'V-75307'
  tag rid: 'SV-89987r1_rule'
  tag stig_id: 'ADBP-XI-001310'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81923r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
