control 'SV-85337' do
  title 'Add-on Management functionality must be allowed.'
  desc 'Internet Explorer add-ons are pieces of code, run in Internet Explorer, to provide additional functionality. Rogue add-ons may contain viruses or other malicious code. Disabling or not configuring this setting could allow malicious code or users to become active on user computers or the network. For example, a malicious user can monitor and then use keystrokes users type into Internet Explorer. Even legitimate add-ons may demand resources, compromising the performance of Internet Explorer, and the operating systems for user computers.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Add-on Management" is set to "Enabled" and 'winproj.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT

Criteria: If the value winproj.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Add-on Management" to "Enabled" and place a check in the 'winproj.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Project 2016'
  tag check_id: 'C-71195r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70713'
  tag rid: 'SV-85337r1_rule'
  tag stig_id: 'DTOO126'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77037r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
