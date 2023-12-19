control 'SV-59467' do
  title 'Active scripting must be disallowed (Restricted Sites Zone).'
  desc 'Active scripts hosted on sites located in this zone are more likely to contain malicious code. Active scripting must have a level of protection based upon the site being accessed. This policy setting allows you to manage whether script code on pages in the zone are run.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow active scripting' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1400" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow active scripting' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49769r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46603'
  tag rid: 'SV-59467r1_rule'
  tag stig_id: 'DTBI133-IE11'
  tag gtitle: 'DTBI133-IE11-Active scripting - Restricted Sites'
  tag fix_id: 'F-50373r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
