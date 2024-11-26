control 'SV-223065' do
  title 'Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether applications may be run and files may be downloaded from an IFRAME reference in the HTML of the pages in this zone. Launching of programs in IFRAME must have a level of protection based upon the site being accessed. If you enable this policy setting, applications can run and files can be downloaded from IFRAMEs on the pages in this zone without user intervention. If you disable this setting, users are prevented from running applications and downloading files from IFRAMEs on the pages in this zone.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Launching applications and files in an IFRAME' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1804" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24738r428745_chk'
  tag severity: 'medium'
  tag gid: 'V-223065'
  tag rid: 'SV-223065r879587_rule'
  tag stig_id: 'DTBI128-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24726r428746_fix'
  tag 'documentable'
  tag legacy: ['SV-59461', 'V-46597']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
