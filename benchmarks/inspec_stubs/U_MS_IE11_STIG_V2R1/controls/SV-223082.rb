control 'SV-223082' do
  title 'Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage restrictions on script-initiated pop-up windows and windows including the title and status bars. If you enable this policy setting, Windows Restrictions security will not apply in this zone. The security zone runs without the added layer of security provided by this feature. If you disable this policy setting, the possible harmful actions contained in script-initiated pop-up windows and windows including the title and status bars cannot be run. This Internet Explorer security feature will be on in this zone as dictated by the Scripted Windows Security Restrictions feature control setting for the process. If you do not configure this policy setting, the possible harmful actions contained in script-initiated pop-up windows and windows including the title and status bars cannot be run. This Internet Explorer security feature will be on in this zone as dictated by the Scripted Windows Security Restrictions feature control setting for the process.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow script-initiated windows without size or position constraints' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2102" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24755r428796_chk'
  tag severity: 'medium'
  tag gid: 'V-223082'
  tag rid: 'SV-223082r428798_rule'
  tag stig_id: 'DTBI390-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24743r428797_fix'
  tag 'documentable'
  tag legacy: ['SV-59503', 'V-46639']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
