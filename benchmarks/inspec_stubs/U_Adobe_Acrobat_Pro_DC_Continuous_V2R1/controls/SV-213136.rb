control 'SV-213136' do
  title 'The Adobe Acrobat Pro DC Continuous Welcome Screen must be disabled.'
  desc 'The Adobe Welcome screen can be distracting. It provides marketing material and also has online links to the Adobe quick tips website, tutorials, blogs, and community forums. When the Adobe Welcome screen is disabled, the Welcome screen will not be populated on application startup.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

If the value for bShowWelcomeScreen is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Welcome Screen' must be set to 'Disabled'.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Welcome Screen' to 'Disabled'.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14373r766560_chk'
  tag severity: 'low'
  tag gid: 'V-213136'
  tag rid: 'SV-213136r766562_rule'
  tag stig_id: 'AADC-CN-001310'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14371r766561_fix'
  tag 'documentable'
  tag legacy: ['SV-94103', 'V-79397']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
