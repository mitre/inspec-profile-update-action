control 'SV-223139' do
  title 'Security Warning for unsafe files must be disallowed (Restricted Sites zone).'
  desc %q(This policy setting controls whether or not the 'Open File - Security Warning' message appears when the user tries to open executable files or other potentially unsafe files (from an intranet file shared by using Windows Explorer, for example). If you enable this policy setting and set the drop-down box to "Enable", these files open without a security warning. If you set the drop-down box to "Prompt", a security warning appears before the files open. If you disable this policy these files do not open. If you do not configure this policy setting, the user can configure how the computer handles these files.)
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Show security warning for potentially unsafe files' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1806" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Show security warning for potentially unsafe files' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24812r428967_chk'
  tag severity: 'medium'
  tag gid: 'V-223139'
  tag rid: 'SV-223139r428969_rule'
  tag stig_id: 'DTBI870-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24800r428968_fix'
  tag 'documentable'
  tag legacy: ['SV-59755', 'V-46889']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
