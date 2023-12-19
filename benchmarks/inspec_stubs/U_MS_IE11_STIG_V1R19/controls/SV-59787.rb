control 'SV-59787' do
  title '.NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone).'
  desc 'It may be possible for someone to host malicious content on a website that takes advantage of these components. This policy setting allows you to manage whether .NET Framework components that are signed with Authenticode can be executed from Internet Explorer. These components include managed controls referenced from an object tag and managed executables referenced from a link. If you enable this policy setting, Internet Explorer will execute signed managed components. If you select "Prompt" in the drop-down box, Internet Explorer will prompt the user to determine whether to execute signed managed components. If you disable this policy setting, Internet Explorer will not execute signed managed components. If you do not configure this policy setting, Internet Explorer will not execute signed managed components.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Run .NET Framework-reliant components signed with Authenticode' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2001" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49959r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46921'
  tag rid: 'SV-59787r1_rule'
  tag stig_id: 'DTBI930-IE11'
  tag gtitle: 'DTBI930-IE11-.NET w/Authenticode signed - Internet'
  tag fix_id: 'F-50659r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001687']
  tag nist: ['SC-18 (2)']
end
