control 'SV-40617' do
  title 'Active scripting must be disallowed (Restricted Sites Zone).'
  desc 'Active scripts hosted on sites located in this zone are more likely to contain malicious code.  Active scripting must have a level of protection based upon the site being accessed.  This policy setting allows you to manage whether script code on pages in the zone are run.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Allow active scripting” must be “Enabled” and “Disable” selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1400 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Allow active scripting” to “Enabled” and select “Disable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39360r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6308'
  tag rid: 'SV-40617r1_rule'
  tag stig_id: 'DTBI133'
  tag gtitle: 'DTBI133-Active scripting - Restricted Sites'
  tag fix_id: 'F-34471r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
