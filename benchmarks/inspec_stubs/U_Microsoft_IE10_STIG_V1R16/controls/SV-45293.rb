control 'SV-45293' do
  title 'Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone).'
  desc 'This policy setting controls whether a page may control embedded WebBrowser control via script. Scripted code hosted on sites located in this zone is more likely to contain malicious code. If you enable this policy setting, script access to the WebBrowser control is allowed. If you disable this policy setting, script access to the WebBrowser control is not allowed. If you do not configure this policy setting, script access to the WebBrowser control can be enabled or disabled by the user. By default, script access to the WebBrowser control is only allowed in the Local Machine and Intranet Zones.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow scripting of Internet Explorer WebBrowser controls" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1206 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow scripting of Internet Explorer WebBrowser controls" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42641r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22152'
  tag rid: 'SV-45293r1_rule'
  tag stig_id: 'DTBI800'
  tag gtitle: 'DTBI800 - Browser scripting control - Internet'
  tag fix_id: 'F-38689r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
