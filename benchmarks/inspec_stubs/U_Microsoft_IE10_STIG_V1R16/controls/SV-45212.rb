control 'SV-45212' do
  title 'Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).'
  desc 'Content hosted on sites located in the Internet zone are likely to contain malicious payloads and therefore this feature should be blocked for this zone. Drag and drop or copy and paste files must have a level of protection based upon the site being accessed.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow drag and drop or copy and paste files" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value for 1802 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow drag and drop or copy and paste files" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42560r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6253'
  tag rid: 'SV-45212r1_rule'
  tag stig_id: 'DTBI036'
  tag gtitle: 'DTBI036-Drag and drop or copy and paste-Internet'
  tag fix_id: 'F-38608r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
