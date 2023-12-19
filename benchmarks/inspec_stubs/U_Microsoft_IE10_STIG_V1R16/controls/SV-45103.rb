control 'SV-45103' do
  title 'Automatic checking for Internet Explorer updates must be disallowed.'
  desc 'This policy setting allows you to manage whether Internet Explorer checks the Internet for newer versions. When Internet Explorer is set to do this, the checks occur approximately every 30 days, and users are prompted to install new versions as they become available. If you enable this policy setting, Internet Explorer checks the Internet for a new version approximately every 30 days and prompts the user to download new versions when they are available. Newer versions might not comply with the Internet Explorer version requirements of the organization.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel-> Advanced Page-> "Automatically check for Internet Explorer updates" must be "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value NoUpdateCheck is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel-> Advanced Page-> "Automatically check for Internet Explorer updates" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42460r1_chk'
  tag severity: 'medium'
  tag gid: 'V-30777'
  tag rid: 'SV-45103r1_rule'
  tag stig_id: 'DTBI775'
  tag gtitle: 'DTBI775 - Internet Explorer Update Checking'
  tag fix_id: 'F-38502r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
