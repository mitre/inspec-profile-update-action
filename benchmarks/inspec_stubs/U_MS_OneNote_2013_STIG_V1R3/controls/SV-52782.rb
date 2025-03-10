control 'SV-52782' do
  title 'Scripted Window Security must be enforced.'
  desc "Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users' computers in some manner. Disabling or not configuring this setting allows unknown websites to:
-Create browser windows appearing to be from the local operating system.
-Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input.
-Overlay parent windows with their own browser windows to hide important system information, choices or prompts."
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" is set to set to "Enabled" and 'onent.exe' is checked. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS

Criteria: If the value onenote.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Scripted Window Security Restrictions" to "Enabled" and 'onent.exe' is checked.)
  impact 0.5
  ref 'DPMS Target Microsoft OneNote 2013'
  tag check_id: 'C-47111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26588'
  tag rid: 'SV-52782r1_rule'
  tag stig_id: 'DTOO124'
  tag gtitle: 'DTOO124 - Scripted Window Security'
  tag fix_id: 'F-45708r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
