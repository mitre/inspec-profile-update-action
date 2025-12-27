control 'SV-48216' do
  title 'Zone information must be preserved when saving attachments.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: SaveZoneInformation

Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Do not preserve zone information in file attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14268'
  tag rid: 'SV-48216r1_rule'
  tag stig_id: 'WN08-UC-000009'
  tag gtitle: 'Attachment Mgr - Preserve Zone Info'
  tag fix_id: 'F-41352r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
