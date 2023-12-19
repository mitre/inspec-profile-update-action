control 'SV-45491' do
  title 'When uploading files to a server, the local directory path must be excluded (Restricted Sites zone).'
  desc 'This policy setting controls whether or not the local path information will be sent when uploading a file via a HTML form. If the local path information is sent, some information may be unintentionally revealed to the server. If you do not configure this policy setting, the user can choose whether path information will be sent when uploading a file via a form. By default, path information will be sent.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Include local path when user is uploading files to a server" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 160A is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Include local path when user is uploading files to a server" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42840r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22158'
  tag rid: 'SV-45491r1_rule'
  tag stig_id: 'DTBI860'
  tag gtitle: 'DTBI860 - Local directory paths - Restricted'
  tag fix_id: 'F-38889r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
