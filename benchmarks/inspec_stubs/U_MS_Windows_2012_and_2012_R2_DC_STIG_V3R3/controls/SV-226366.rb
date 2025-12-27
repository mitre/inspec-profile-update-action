control 'SV-226366' do
  title 'Mechanisms for removing zone information from file attachments must be hidden.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.  This setting prevents users from manually removing zone information from saved file attachments.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: HideZoneInfoOnProperties

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Hide mechanisms to remove zone information" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28068r476942_chk'
  tag severity: 'medium'
  tag gid: 'V-226366'
  tag rid: 'SV-226366r794686_rule'
  tag stig_id: 'WN12-UC-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28056r476943_fix'
  tag 'documentable'
  tag legacy: ['SV-53004', 'V-14269']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
