control 'SV-53577' do
  title 'Protection from zone elevation must be enforced.'
  desc "Internet Explorer places restrictions on each web page users can use the browser to open. Web pages on a user's local computer have the fewest security restrictions and reside in the Local Machine zone, making this security zone a prime target for malicious users and code. Disabling or not configuring this setting could allow pages in the Internet zone to navigate to pages in the Local Machine zone to then run code to elevate privileges. This could allow malicious code or users to become active on user computers or the network."
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Protection From Zone Elevation" is set to "Enabled" and 'winword.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION

Criteria: If the value winword.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Protection From Zone Elevation" to "Enabled" and 'winword.exe' is checked.)
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47725r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26585'
  tag rid: 'SV-53577r1_rule'
  tag stig_id: 'DTOO209'
  tag gtitle: 'DTOO209 - Zone Elevation Protection'
  tag fix_id: 'F-46501r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
