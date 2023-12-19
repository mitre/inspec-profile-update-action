control 'SV-29757' do
  title 'Notify antivirus when file attachments are opened.'
  desc 'This check verifies that antivirus programs are notified when a user opens a file attachment.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name:  ScanWithAntiVirus

Type:  REG_DWORD
Value:  3'
  desc 'fix', 'Configure policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> “Notify antivirus programs when opening attachments” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11760r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14270'
  tag rid: 'SV-29757r1_rule'
  tag gtitle: 'Attachment Mgr - Scan with Antivirus'
  tag fix_id: 'F-13608r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
