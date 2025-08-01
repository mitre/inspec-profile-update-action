control 'SV-228422' do
  title 'Navigation to URLs embedded in Office products must be blocked.'
  desc 'To protect users from attacks, Internet Explorer usually does not attempt to load malformed URLs. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer attempts to load a malformed URL, a security risk could occur.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Navigate URL" is set to "Enabled" and 'outlook.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL

Criteria: If the value outlook.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Navigate URL" to "Enabled" and place a check in the 'outlook.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30655r497588_chk'
  tag severity: 'medium'
  tag gid: 'V-228422'
  tag rid: 'SV-228422r508021_rule'
  tag stig_id: 'DTOO123'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30640r497589_fix'
  tag 'documentable'
  tag legacy: ['SV-85739', 'V-71115']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
