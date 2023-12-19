control 'SV-45054' do
  title '.NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone).'
  desc 'This policy setting allows you to manage whether .NET Framework reliant components that are signed with Authenticode can be executed from Internet Explorer. It may be possible for malicious content hosted on a website to take advantage of these components. These components include managed controls referenced from an object tag and managed executables referenced from a link. If you enable this policy setting, Internet Explorer will execute signed managed components. If you select Prompt in the drop-down box, Internet Explorer will prompt the user to determine whether to execute signed managed components. If you disable this policy setting, Internet Explorer will not execute signed managed components. If you do not configure this policy setting, Internet Explorer will execute signed managed components.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run .NET Framework-reliant components signed with Authenticode" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2001 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run .NET Framework-reliant components signed with Authenticode" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42430r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15561'
  tag rid: 'SV-45054r1_rule'
  tag stig_id: 'DTBI655'
  tag gtitle: 'DTBI655 - .NET w/Authenticode signed - Restricted'
  tag fix_id: 'F-38464r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
