control 'SV-45318' do
  title 'Status bar updates via script must be disallowed (Restricted Sites zone).'
  desc 'A script running in the zone could cause false information to be displayed on the status bar, which could confuse the user and cause an undesirable action. This policy setting allows you to manage whether script is allowed to update the status bar within the zone. If you enable this policy setting, script is allowed to update the status bar. If you disable this policy setting, script is not allowed to update the status bar. If you do not configure this policy setting, status bar updates via scripts will be disabled.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone "Allow updates to status bar via script" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2103 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone "Allow updates to status bar via script" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22638'
  tag rid: 'SV-45318r1_rule'
  tag stig_id: 'DTBI950'
  tag gtitle: 'DTBI950 - Status bar update by script - Restricted'
  tag fix_id: 'F-38714r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
