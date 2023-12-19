control 'SV-225069' do
  title 'Zone information must be preserved when saving attachments.'
  desc 'Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', 'The default behavior is for Windows to mark file attachments with their zone information.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "2", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Windows to mark file attachments with their zone information.

If this needs to be corrected, configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Attachment Manager >> "Do not preserve zone information in file attachments" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26760r466109_chk'
  tag severity: 'medium'
  tag gid: 'V-225069'
  tag rid: 'SV-225069r569186_rule'
  tag stig_id: 'WN16-UC-000030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26748r466110_fix'
  tag 'documentable'
  tag legacy: ['SV-88391', 'V-73727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
