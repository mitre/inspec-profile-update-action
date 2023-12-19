control 'SV-226367' do
  title 'The system must notify antivirus when file attachments are opened.'
  desc 'Attaching malicious files is a known avenue of attack.  This setting configures the system to notify antivirus programs when a user opens a file attachment.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: ScanWithAntiVirus

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Notify antivirus programs when opening attachments" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28069r476945_chk'
  tag severity: 'medium'
  tag gid: 'V-226367'
  tag rid: 'SV-226367r794687_rule'
  tag stig_id: 'WN12-UC-000011'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28057r476946_fix'
  tag 'documentable'
  tag legacy: ['SV-53006', 'V-14270']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
