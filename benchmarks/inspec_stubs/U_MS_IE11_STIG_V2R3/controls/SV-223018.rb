control 'SV-223018' do
  title 'The Download unsigned ActiveX controls property must be disallowed (Internet zone).'
  desc 'Unsigned code is potentially harmful, especially when coming from an untrusted zone. This policy setting allows you to manage whether users may download unsigned ActiveX controls from the zone. If you enable this policy setting, users can run unsigned controls without user intervention. If you select "Prompt" in the drop-down box, users are queried to choose whether to allow the unsigned control to run. If you disable this policy setting, users cannot run unsigned controls. If you do not configure this policy setting, users cannot run unsigned controls.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Download unsigned ActiveX controls' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1004" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Download unsigned ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24691r428604_chk'
  tag severity: 'medium'
  tag gid: 'V-223018'
  tag rid: 'SV-223018r428606_rule'
  tag stig_id: 'DTBI023-IE11'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-24679r428605_fix'
  tag 'documentable'
  tag legacy: ['SV-59347', 'V-46483']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
