control 'SV-223068' do
  title 'Active scripting must be disallowed (Restricted Sites Zone).'
  desc 'Active scripts hosted on sites located in this zone are more likely to contain malicious code. Active scripting must have a level of protection based upon the site being accessed. This policy setting allows you to manage whether script code on pages in the zone are run.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow active scripting' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1400" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow active scripting' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24741r428754_chk'
  tag severity: 'medium'
  tag gid: 'V-223068'
  tag rid: 'SV-223068r879587_rule'
  tag stig_id: 'DTBI133-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24729r428755_fix'
  tag 'documentable'
  tag legacy: ['SV-59467', 'V-46603']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
