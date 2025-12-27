control 'SV-59375' do
  title 'Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).'
  desc 'Content hosted on sites located in the Internet zone are likely to contain malicious payloads and therefore this feature should be blocked for this zone. Drag and drop or copy and paste files must have a level of protection based upon the site being accessed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow drag and drop or copy and paste files' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value for "1802" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49701r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46511'
  tag rid: 'SV-59375r1_rule'
  tag stig_id: 'DTBI036-IE11'
  tag gtitle: 'DTBI036-IE11-Drag and drop or copy and paste - Internet'
  tag fix_id: 'F-50301r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
