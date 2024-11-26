control 'SV-85647' do
  title 'Protection from zone elevation must be enforced.'
  desc "Internet Explorer places restrictions on each web page users can use the browser to open. Web pages on a user's local computer have the fewest security restrictions and reside in the Local Machine zone, making this security zone a prime target for malicious users and code. Disabling or not configuring this setting could allow pages in the Internet zone to navigate to pages in the Local Machine zone to then run code to elevate privileges. This could allow malicious code or users to become active on user computers or the network."
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Protection From Zone Elevation" is set to "Enabled" and 'excel.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION

Criteria: If the value excel.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Protection From Zone Elevation" to "Enabled" and place a check in the 'excel.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71451r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71023'
  tag rid: 'SV-85647r1_rule'
  tag stig_id: 'DTOO209'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-77355r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
