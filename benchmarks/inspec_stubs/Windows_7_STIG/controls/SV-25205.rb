control 'SV-25205' do
  title 'Preserve zone information when saving attachments.'
  desc 'This check verifies that file attachments are marked with their zone of origin allowing Windows to determine risk.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name:  SaveZoneInformation

Type:  REG_DWORD
Value:  2'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> “Do not preserve zone information in file attachments” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-11758r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14268'
  tag rid: 'SV-25205r1_rule'
  tag gtitle: 'Attachment Mgr - Preserve Zone Info'
  tag fix_id: 'F-13606r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
