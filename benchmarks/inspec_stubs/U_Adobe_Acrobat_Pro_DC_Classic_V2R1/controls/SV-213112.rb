control 'SV-213112' do
  title 'The Adobe Acrobat Pro DC Classic Welcome Screen must be disabled.'
  desc 'The Adobe Welcome screen can be distracting. It provides marketing material and also has online links to the Adobe quick tips website, tutorials, blogs, and community forums. When the Adobe Welcome screen is disabled, the Welcome screen will not be populated on application startup.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

If the value for bShowWelcomeScreen is not set to "0" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Welcome Screen' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cWelcomeScreen" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cWelcomeScreen

Value Name: bShowWelcomeScreen
Type: REG_DWORD
Value: 0

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Welcome Screen' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14350r478155_chk'
  tag severity: 'low'
  tag gid: 'V-213112'
  tag rid: 'SV-213112r557504_rule'
  tag stig_id: 'AADC-CL-001310'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14348r478156_fix'
  tag 'documentable'
  tag legacy: ['V-80149', 'SV-94853']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
