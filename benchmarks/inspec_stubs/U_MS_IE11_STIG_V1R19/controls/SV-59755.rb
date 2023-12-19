control 'SV-59755' do
  title 'Security Warning for unsafe files must be disallowed (Restricted Sites zone).'
  desc %q(This policy setting controls whether or not the 'Open File - Security Warning' message appears when the user tries to open executable files or other potentially unsafe files (from an intranet file shared by using Windows Explorer, for example). If you enable this policy setting and set the drop-down box to "Enable", these files open without a security warning. If you set the drop-down box to "Prompt", a security warning appears before the files open. If you disable this policy these files do not open. If you do not configure this policy setting, the user can configure how the computer handles these files.)
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Show security warning for potentially unsafe files' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1806" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Show security warning for potentially unsafe files' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49947r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46889'
  tag rid: 'SV-59755r1_rule'
  tag stig_id: 'DTBI870-IE11'
  tag gtitle: 'DTBI870-IE11-Security Warning for unsafe files - Restricted Sites'
  tag fix_id: 'F-50625r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001274']
  tag nist: ['SI-4 (12)']
end
