control 'SV-53618' do
  title 'Internet Explorer Bind to Object functionality must be enabled.'
  desc 'Internet Explorer performs a number of safety checks before initializing an ActiveX control. It will not initialize a control if the kill bit for the control is set in the registry, or if the security settings for the zone in which the control is located do not allow it to be initialized.
This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). A security risk could occur if potentially dangerous controls are allowed to load.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Bind to Object" is set to "Enabled" and a check in the 'excel.exe' check box is set to present.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT

Criteria: If the value excel.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Bind to Object" to "Enabled" and place a check in the 'excel.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17174'
  tag rid: 'SV-53618r1_rule'
  tag stig_id: 'DTOO111'
  tag gtitle: 'DTOO111 - Enable IE Bind to Object'
  tag fix_id: 'F-46544r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
