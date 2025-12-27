control 'SV-253478' do
  title 'Zone information must be preserved when saving attachments.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', 'The default behavior is for Windows to mark file attachments with their zone information.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Windows to mark file attachments with their zone information.

To correct this, configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Attachment Manager >> "Do not preserve zone information in file attachments" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56931r829516_chk'
  tag severity: 'medium'
  tag gid: 'V-253478'
  tag rid: 'SV-253478r829518_rule'
  tag stig_id: 'WN11-UC-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56881r829517_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
