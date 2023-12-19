control 'SV-85933' do
  title 'Scripted Window Security must be enforced.'
  desc "Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users' computers in some manner. Disabling or not configuring this setting allows unknown websites to:
-Create browser windows appearing to be from the local operating system.
-Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input.
-Overlay parent windows with their own browser windows to hide important system information, choices or prompts."
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" is set to "Enabled" and 'groove.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS

Criteria: If the value groove.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" to "Enabled" and place a check in the 'groove.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive 2016'
  tag check_id: 'C-71705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71309'
  tag rid: 'SV-85933r1_rule'
  tag stig_id: 'DTOO124'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-77621r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
