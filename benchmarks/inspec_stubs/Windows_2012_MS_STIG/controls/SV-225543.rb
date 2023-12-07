control 'SV-225543' do
  title 'Users must be prevented from sharing files in their profiles.'
  desc 'Allowing users to share files in their profiles may provide unauthorized access or result in the exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoInPlaceSharing

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Network Sharing -> "Prevent users from sharing files within their profile" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27242r471971_chk'
  tag severity: 'medium'
  tag gid: 'V-225543'
  tag rid: 'SV-225543r569185_rule'
  tag stig_id: 'WN12-UC-000012'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-27230r471972_fix'
  tag 'documentable'
  tag legacy: ['SV-53140', 'V-15727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
