control 'SV-85333' do
  title 'Navigation to URLs embedded in Office products must be blocked.'
  desc 'To protect users from attacks, Internet Explorer usually does not attempt to load malformed URLs. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer attempts to load a malformed URL, a security risk could occur.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Navigate URL" is set to "Enabled" and 'winproj.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL

Criteria: If the value winproj.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Navigate URL" to "Enabled" and place a check in the 'winproj.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Project 2016'
  tag check_id: 'C-71191r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70709'
  tag rid: 'SV-85333r1_rule'
  tag stig_id: 'DTOO123'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
