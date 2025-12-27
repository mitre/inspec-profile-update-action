control 'SV-45159' do
  title 'Font downloads must be disallowed (Restricted Sites zone).'
  desc 'It is possible that a font could include malformed data that would cause Internet Explorer to crash when it attempts to load and render the font. Downloads of fonts can sometimes contain malicious code. Files should not be downloaded from restricted sites. This policy setting allows you to manage whether pages of the zone may download HTML fonts.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow font downloads" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1604 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow font downloads" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42503r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6295'
  tag rid: 'SV-45159r1_rule'
  tag stig_id: 'DTBI120'
  tag gtitle: 'DTBI120-Font download control - Restricted Sites'
  tag fix_id: 'F-38556r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
