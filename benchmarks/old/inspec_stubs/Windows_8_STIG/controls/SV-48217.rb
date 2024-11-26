control 'SV-48217' do
  title 'Mechanisms for removing zone information from file attachments must be hidden.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.  This setting prevents users from manually removing zone information from saved file attachments.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: HideZoneInfoOnProperties

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Hide mechanisms to remove zone information" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14269'
  tag rid: 'SV-48217r1_rule'
  tag stig_id: 'WN08-UC-000010'
  tag gtitle: 'Attachment Mgr - Hide Mech to Remove Zone Info'
  tag fix_id: 'F-41353r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
