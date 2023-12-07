control 'SV-25206' do
  title 'Hide mechanism for removing zone information from file attachments.'
  desc 'This check verifies that users cannot manually remove zone information from saved file attachments.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name:  HideZoneInfoOnProperties

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> “Hide mechanisms to remove zone information” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-11759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14269'
  tag rid: 'SV-25206r1_rule'
  tag gtitle: 'Attachment Mgr - Hide Mech to Remove Zone Info'
  tag fix_id: 'F-13607r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
