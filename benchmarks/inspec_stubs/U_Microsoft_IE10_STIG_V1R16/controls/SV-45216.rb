control 'SV-45216' do
  title 'Installation of desktop items must be disallowed (Restricted Sites zone).'
  desc 'Active Desktop items could contain links to unauthorized websites or other undesirable content. It is prudent to prevent users from installing desktop items from this security zone. Installation of items must have a level of protection based upon the site being accessed. This policy setting allows you to manage whether users can install Active Desktop items from this zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow installation of desktop items" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1800 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow installation of desktop items" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42564r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6302'
  tag rid: 'SV-45216r1_rule'
  tag stig_id: 'DTBI127'
  tag gtitle: 'DTBI127-Installation of desktop items - Restricted'
  tag fix_id: 'F-38612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
