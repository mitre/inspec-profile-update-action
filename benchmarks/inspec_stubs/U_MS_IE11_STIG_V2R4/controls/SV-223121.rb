control 'SV-223121' do
  title 'Scripting of Java applets must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether applets are exposed to scripts within the zone. If you enable this policy setting, scripts can access applets automatically without user intervention. If you select "Prompt" in the drop-down box, users are queried to choose whether to allow scripts to access applets. If you disable this policy setting, scripts are prevented from accessing applets. If you do not configure this policy setting, scripts can access applets automatically without user intervention.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Scripting of Java applets' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1402" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Scripting of Java applets' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24794r428913_chk'
  tag severity: 'medium'
  tag gid: 'V-223121'
  tag rid: 'SV-223121r879587_rule'
  tag stig_id: 'DTBI670-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24782r428914_fix'
  tag 'documentable'
  tag legacy: ['SV-59667', 'V-46801']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
