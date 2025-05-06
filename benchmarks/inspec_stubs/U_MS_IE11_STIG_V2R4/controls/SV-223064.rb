control 'SV-223064' do
  title 'Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone).'
  desc 'Content hosted on sites located in the Restricted Sites zone are more likely to contain malicious payloads and therefore this feature should be blocked for this zone. Drag and drop or copy and paste files must have a level of protection based upon the site being accessed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow drag and drop or copy and paste files' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1802" is REG_DWORD=3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24737r428742_chk'
  tag severity: 'medium'
  tag gid: 'V-223064'
  tag rid: 'SV-223064r879587_rule'
  tag stig_id: 'DTBI126-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24725r428743_fix'
  tag 'documentable'
  tag legacy: ['SV-59457', 'V-46593']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
