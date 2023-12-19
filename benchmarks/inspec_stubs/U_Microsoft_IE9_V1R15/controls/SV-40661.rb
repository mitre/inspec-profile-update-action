control 'SV-40661' do
  title 'Automatic prompting for file downloads must be disallowed (Restricted Sites zone).'
  desc 'This policy setting determines whether users will be prompted for non user-initiated file downloads. Regardless of this setting, users will receive file download dialogs for user-initiated downloads. Users may accept downloads that they did not request, those downloaded files may include malicious code. If you enable this setting, users will receive a file download dialog for automatic download attempts. If you disable or do not configure this setting, file downloads that are not user-initiated will be blocked, and users will see the Information Bar instead of the file download dialog. Users can then click the Information Bar to allow the file download prompt.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Automatic prompting for file downloads" must be “Enabled” and "Disable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2200 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Automatic prompting for file downloads" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15546'
  tag rid: 'SV-40661r1_rule'
  tag stig_id: 'DTBI580'
  tag gtitle: 'DTBI580 - Prompt for file downloads - Restricted'
  tag fix_id: 'F-34516r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
