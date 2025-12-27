control 'SV-40606' do
  title 'The Allow META REFRESH property must be disallowed (Restricted Sites zone).'
  desc "It is possible that users will unknowingly be redirected to a site hosting malicious content. Allow META REFRESH must have level of protection based upon the site being browsed. This policy setting allows you to manage whether a user's browser can be redirected to another web page if the author of the web page uses the Meta Refresh setting to redirect browsers to another web page."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Allow META REFRESH” must be “Enabled” and “Disable” selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1608 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Allow META REFRESH” to “Enabled” and select “Disable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39352r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6298'
  tag rid: 'SV-40606r1_rule'
  tag stig_id: 'DTBI123'
  tag gtitle: 'DTBI123 - META REFRESH - Restricted Sites'
  tag fix_id: 'F-34463r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
