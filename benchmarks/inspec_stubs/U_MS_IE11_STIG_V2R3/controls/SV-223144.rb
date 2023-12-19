control 'SV-223144' do
  title '.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).'
  desc 'Unsigned components are more likely to contain malicious code and it is more difficult to determine the author of the application - therefore they should be avoided if possible. This policy setting allows you to manage whether .NET Framework components that are not signed with Authenticode can be executed from Internet Explorer. These components include managed controls referenced from an object tag and managed executables referenced from a link. If you enable this policy setting, Internet Explorer will execute unsigned managed components. If you select "Prompt" in the drop-down box, Internet Explorer will prompt the user to determine whether to execute unsigned managed components. If you disable this policy setting, Internet Explorer will not execute unsigned managed components. If you do not configure this policy setting, Internet Explorer will not execute unsigned managed components.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Run .NET Framework-reliant components not signed with Authenticode' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2004" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24817r428982_chk'
  tag severity: 'medium'
  tag gid: 'V-223144'
  tag rid: 'SV-223144r428984_rule'
  tag stig_id: 'DTBI920-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24805r428983_fix'
  tag 'documentable'
  tag legacy: ['SV-59773', 'V-46907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
