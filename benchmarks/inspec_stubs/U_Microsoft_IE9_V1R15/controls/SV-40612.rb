control 'SV-40612' do
  title 'Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether applications may be run and files may be downloaded from an IFRAME reference in the HTML of the pages in this zone. Launching of programs in IFRAME must have a level of protection based upon the site being accessed. If you enable this policy setting, applications can run and files can be downloaded from IFRAMEs on the pages in this zone without user intervention. If you disable this setting, users are prevented from running applications and downloading files from IFRAMEs on the pages in this zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Launching applications and files in an IFRAME" must be “Enabled” and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1804 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Launching applications and files in an IFRAME" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39356r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6303'
  tag rid: 'SV-40612r1_rule'
  tag stig_id: 'DTBI128'
  tag gtitle: 'DTBI128 - Programs and files in IFRAME-Restricted'
  tag fix_id: 'F-34467r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
