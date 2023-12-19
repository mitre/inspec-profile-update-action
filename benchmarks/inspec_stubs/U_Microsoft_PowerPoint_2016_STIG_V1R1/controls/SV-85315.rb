control 'SV-85315' do
  title 'Scripted Window Security must be enforced in PowerPoint Viewer.'
  desc "Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users' computers in some manner. Disabling or not configuring this setting allows unknown websites to:
-Create browser windows appearing to be from the local operating system.
-Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input.
-Overlay parent windows with their own browser windows to hide important system information, choices or prompts."
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" is set to "Enabled" and 'pptview.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS

Criteria: If the value pptview.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" to "Enabled" and place a check in he 'pptview.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71171r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70691'
  tag rid: 'SV-85315r1_rule'
  tag stig_id: 'DTOO505'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-77013r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
