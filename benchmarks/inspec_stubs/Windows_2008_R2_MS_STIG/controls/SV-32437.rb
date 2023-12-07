control 'SV-32437' do
  title 'Users will be prevented from sharing files in their profiles.'
  desc 'This check verifies that users are prevented from sharing files.'
  desc 'check', 'Note:  This setting is in HKEY_CURRENT_USER, not HKEY_LOCAL_MACHINE

If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_CURRENT_USER
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoInPlaceSharing

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Note: This setting is under USER Configuration, not COMPUTER Configuration.

Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Network Sharing “Prevent users from sharing files within their profile” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15415r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15727'
  tag rid: 'SV-32437r1_rule'
  tag gtitle: 'User Network Sharing'
  tag fix_id: 'F-29053r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
