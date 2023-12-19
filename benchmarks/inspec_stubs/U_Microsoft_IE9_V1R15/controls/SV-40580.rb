control 'SV-40580' do
  title 'Logon options must be configured to prompt (Internet zone).'
  desc 'Users could submit credentials to servers operated by malicious people who could then attempt to connect to legitimate servers with those captured credentials.  Care must be taken with user credentials, automatic logon performance, and how default Windows credentials are passed to web sites.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Logon options" must be “Enabled” and "Prompt for user name and password" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1A00 is REG_DWORD = 65536 (decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Logon options" to “Enabled” and select "Prompt for user name and password" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39338r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6262'
  tag rid: 'SV-40580r1_rule'
  tag stig_id: 'DTBI046'
  tag gtitle: 'DTBI046-User Authentication-Logon - Internet Zone'
  tag fix_id: 'F-34446r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
