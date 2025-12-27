control 'SV-213159' do
  title 'Adobe Reader DC must disable the Adobe Welcome Screen.'
  desc 'The Adobe Reader DC Welcome screen can be distracting and also has online links to the Adobe quick tips website, tutorials, blogs and community forums.

When the Adobe Reader DC Welcome screen is disabled the Welcome screen will not be populated on application startup.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cWelcomeScreen" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

If the value for bShowWelcomeScreen is not set to “0” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cWelcomeScreen" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14395r276620_chk'
  tag severity: 'low'
  tag gid: 'V-213159'
  tag rid: 'SV-213159r557349_rule'
  tag stig_id: 'ARDC-CL-000115'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14393r276621_fix'
  tag 'documentable'
  tag legacy: ['SV-80285', 'V-65795']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
