control 'SV-45482' do
  title 'Rule Title: Userdata persistence must be disallowed (Restricted Sites zone).'
  desc "Userdata persistence must have a level of protection based upon the site being accessed. This policy setting allows you to manage the preservation of information in the browser's history, in favorites, in an XML store, or directly within a web page saved to disk. When a user returns to a persisted page, the state of the page can be restored if this policy setting is not appropriately configured."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Userdata persistence" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1606 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Userdata persistence" to "Enabled", and select "Disable" from the drop-down box'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6307'
  tag rid: 'SV-45482r1_rule'
  tag stig_id: 'DTBI132'
  tag gtitle: 'DTBI132-Userdata persistence - Restricted Sites'
  tag fix_id: 'F-38879r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
