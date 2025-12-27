control 'SV-223081' do
  title 'Script-initiated windows without size or position constraints must be disallowed (Internet zone).'
  desc 'This policy setting allows you to manage restrictions on script-initiated pop-up windows and windows including the title and status bars. If you enable this policy setting, Windows Restrictions security will not apply in this zone. The security zone runs without the added layer of security provided by this feature. If you disable this policy setting, the possible harmful actions contained in script-initiated pop-up windows and windows including the title and status bars cannot be run. This Internet Explorer security feature will be on in this zone as dictated by the Scripted Windows Security Restrictions feature control setting for the process. If you do not configure this policy setting, the possible harmful actions contained in script-initiated pop-up windows and windows including the title and status bars cannot be run. This Internet Explorer security feature will be on in this zone as dictated by the Scripted Windows Security Restrictions feature control setting for the process.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow script-initiated windows without size or position constraints' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2102" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24754r428793_chk'
  tag severity: 'medium'
  tag gid: 'V-223081'
  tag rid: 'SV-223081r428795_rule'
  tag stig_id: 'DTBI385-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24742r428794_fix'
  tag 'documentable'
  tag legacy: ['SV-59501', 'V-46637']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
