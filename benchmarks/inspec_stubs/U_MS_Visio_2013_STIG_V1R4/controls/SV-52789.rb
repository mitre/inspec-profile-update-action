control 'SV-52789' do
  title 'The Internet Explorer Bind to Object functionality must be enabled.'
  desc 'Internet Explorer performs a number of safety checks before initializing an ActiveX control. It will not initialize a control if the kill bit for the control is set in the registry, or if the security settings for the zone in which the control is located do not allow it to be initialized.
This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). A security risk could occur if potentially dangerous controls are allowed to load.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Bind to object" is set to "Enabled" and 'visio.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT

Criteria: If the value visio.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Bind to object" to "Enabled" and place check in 'visio.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Visio 2013'
  tag check_id: 'C-47118r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40731'
  tag rid: 'SV-52789r1_rule'
  tag stig_id: 'DTOO111'
  tag gtitle: 'DTOO111 - IE Bind to Object'
  tag fix_id: 'F-45715r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
