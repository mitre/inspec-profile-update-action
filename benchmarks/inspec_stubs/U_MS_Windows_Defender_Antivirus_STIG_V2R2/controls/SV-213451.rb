control 'SV-213451' do
  title 'Windows Defender AV must be configured to turn on e-mail scanning.'
  desc 'This policy setting allows you to configure e-mail scanning. When e-mail scanning is enabled the engine will parse the mailbox and mail files according to their specific format in order to analyze the mail bodies and attachments. Several e-mail formats are currently supported for example: pst (Outlook) dbx mbx mime (Outlook Express) binhex (Mac). If you enable this setting e-mail scanning will be enabled. If you disable or do not configure this setting e-mail scanning will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Turn on e-mail scanning" is set to "Enabled".
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "DisableEmailScanning" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Turn on e-mail scanning" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14676r314662_chk'
  tag severity: 'medium'
  tag gid: 'V-213451'
  tag rid: 'SV-213451r569189_rule'
  tag stig_id: 'WNDF-AV-000027'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14674r314663_fix'
  tag 'documentable'
  tag legacy: ['SV-89919', 'V-75239']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
