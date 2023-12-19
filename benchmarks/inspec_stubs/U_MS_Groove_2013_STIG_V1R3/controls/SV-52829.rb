control 'SV-52829' do
  title 'Add-on Management functionality must be allowed.'
  desc 'Internet Explorer add-ons are pieces of code, run in Internet Explorer, to provide additional functionality. Rogue add-ons may contain viruses or other malicious code. Disabling or not configuring this setting could allow malicious code or users to become active on user computers or the network. For example, a malicious user can monitor and then use keystrokes users type into Internet Explorer. Even legitimate add-ons may demand resources, compromising the performance of Internet Explorer, and the operating systems for user computers.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Add-on Management" is set to "Enabled" and  'groove.exe' is checked. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT

Criteria: If the value groove.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Add-on Management" to "Enabled" and  'groove.exe' is checked.)
  impact 0.5
  ref 'DPMS Target Microsoft Groove 2013'
  tag check_id: 'C-47146r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40771'
  tag rid: 'SV-52829r1_rule'
  tag stig_id: 'DTOO126'
  tag gtitle: 'DTOO126 - Add-on Management'
  tag fix_id: 'F-45755r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
