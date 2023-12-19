control 'SV-59553' do
  title 'Pop-up Blocker must be enforced (Internet zone).'
  desc 'This policy setting allows you to manage whether unwanted pop-up windows appear. Pop-up windows that are opened when the end user clicks a link are not blocked. If you enable this policy setting, most unwanted pop-up windows are prevented from appearing. If you disable this policy setting, pop-up windows are not prevented from appearing. If you do not configure this policy setting, most unwanted pop-up windows are prevented from appearing.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Use Pop-up Blocker' must be 'Enabled', and 'Enable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1809" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49839r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46689'
  tag rid: 'SV-59553r1_rule'
  tag stig_id: 'DTBI495-IE11'
  tag gtitle: 'DTBI495-IE11-Pop-up blocker - Internet'
  tag fix_id: 'F-50451r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
