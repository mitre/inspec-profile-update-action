control 'SV-48218' do
  title 'The system must notify antivirus when file attachments are opened.'
  desc 'Attaching malicious files is a known avenue of attack.  This setting configures the system to notify antivirus programs when a user opens a file attachment.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: ScanWithAntiVirus

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Notify antivirus programs when opening attachments" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14270'
  tag rid: 'SV-48218r1_rule'
  tag stig_id: 'WN08-UC-000011'
  tag gtitle: 'Attachment Mgr - Scan with Antivirus'
  tag fix_id: 'F-41354r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
