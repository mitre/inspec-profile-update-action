control 'SV-45158' do
  title 'Font downloads must be disallowed (Internet zone).'
  desc 'Downloads of fonts can sometimes contain malicious code. It is possible that a font could include malformed data that would cause Internet Explorer to crash when it attempts to load and render the font. This policy setting allows you to manage whether pages of the zone may download HTML fonts. If you enable this policy setting, HTML fonts can be downloaded automatically. If you enable this policy setting and Prompt is selected in the drop-down box, users are queried whether to allow HTML fonts to download. If you disable this policy setting, HTML fonts are prevented from downloading.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow font downloads" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1604 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow font downloads" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42501r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6248'
  tag rid: 'SV-45158r1_rule'
  tag stig_id: 'DTBI030'
  tag gtitle: 'DTBI030-Font download control - Internet Zone'
  tag fix_id: 'F-38554r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
