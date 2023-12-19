control 'SV-40677' do
  title '.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Site Zone).'
  desc 'This policy setting allows you to manage whether .NET Framework components that are not signed with Authenticode can be executed from Internet Explorer. These components include managed controls referenced from an object tag and managed executables referenced from a link. If you enable this policy setting, Internet Explorer will execute unsigned managed components. If you select Prompt in the drop-down box, Internet Explorer will prompt the user to determine whether to execute unsigned managed components. If you disable this policy setting, Internet Explorer will not execute unsigned managed components. If you do not configure this policy setting, Internet Explorer will execute unsigned managed components.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run .NET Framework-reliant components not signed with Authenticode" must be “Enabled” and "Disable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2004 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run .NET Framework-reliant components not signed with Authenticode" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39407r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15560'
  tag rid: 'SV-40677r1_rule'
  tag stig_id: 'DTBI650'
  tag gtitle: 'DTBI650 - .NET w/Authenticode unsigned-Restricted'
  tag fix_id: 'F-34530r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
