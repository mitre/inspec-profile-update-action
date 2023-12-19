control 'SV-53475' do
  title 'Navigation to URLs embedded in Office products must be blocked in PowerPoint.'
  desc 'To protect users from attacks, Internet Explorer usually does not attempt to load malformed URLs. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer attempts to load a malformed URL, a security risk could occur.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Navigate URL" must be "Enabled" and a check in the 'powerpnt.exe' check box is selected.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL

Criteria: If the value powerpnt.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Navigate URL" to "Enabled" and place a check in the 'powerpnt.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17183'
  tag rid: 'SV-53475r1_rule'
  tag stig_id: 'DTOO123'
  tag gtitle: 'DTOO123-Block Navigation to URL from Office'
  tag fix_id: 'F-46401r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
