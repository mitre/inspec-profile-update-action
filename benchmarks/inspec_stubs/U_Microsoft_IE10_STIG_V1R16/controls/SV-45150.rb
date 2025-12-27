control 'SV-45150' do
  title 'File downloads must be disallowed (Restricted Sites zone).'
  desc 'Sites located in the Restricted Sites Zone are more likely to contain malicious payloads and therefore downloads from this zone should be blocked. Files should not be able to be downloaded from sites that are considered restricted. This policy setting allows you to manage whether file downloads are permitted from the zone. This option is determined by the zone of the page with the link causing the download, not the zone from which the file is delivered.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow file downloads" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1803 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Allow file downloads" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42493r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6294'
  tag rid: 'SV-45150r1_rule'
  tag stig_id: 'DTBI119'
  tag gtitle: 'DTBI119-File download control - Restricted Sites'
  tag fix_id: 'F-38546r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
