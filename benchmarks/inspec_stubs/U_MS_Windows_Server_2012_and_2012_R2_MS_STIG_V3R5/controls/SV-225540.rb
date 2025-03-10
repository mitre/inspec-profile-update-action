control 'SV-225540' do
  title 'Zone information must be preserved when saving attachments.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: SaveZoneInformation

Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Do not preserve zone information in file attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27239r471962_chk'
  tag severity: 'medium'
  tag gid: 'V-225540'
  tag rid: 'SV-225540r569185_rule'
  tag stig_id: 'WN12-UC-000009'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27227r471963_fix'
  tag 'documentable'
  tag legacy: ['SV-53002', 'V-14268']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
