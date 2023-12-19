control 'SV-45111' do
  title 'Automatic prompting for file downloads must be disallowed (Restricted Sites zone).'
  desc 'This policy setting determines whether users will be prompted for non user-initiated file downloads. Regardless of this setting, users will receive file download dialogs for user-initiated downloads. Users may accept downloads that they did not request, and those downloaded files may include malicious code. If you enable this setting, users will receive a file download dialog for automatic download attempts. If you disable or do not configure this setting, file downloads that are not user-initiated will be blocked, and users will see the information bar instead of the file download dialog. Users can then click the information bar to allow the file download prompt.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Automatic prompting for file downloads" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2200 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Automatic prompting for file downloads" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42466r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15546'
  tag rid: 'SV-45111r1_rule'
  tag stig_id: 'DTBI580'
  tag gtitle: 'DTBI580 - Prompt for file downloads - Restricted'
  tag fix_id: 'F-38508r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
