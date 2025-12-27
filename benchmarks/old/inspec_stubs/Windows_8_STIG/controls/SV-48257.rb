control 'SV-48257' do
  title 'Users must be prevented from sharing files in their profiles.'
  desc 'Allowing users to share files in their profiles may provide unauthorized access or result in the exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoInPlaceSharing

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Network Sharing -> "Prevent users from sharing files within their profile" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15727'
  tag rid: 'SV-48257r2_rule'
  tag stig_id: 'WN08-UC-000012'
  tag gtitle: 'User Network Sharing'
  tag fix_id: 'F-41392r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
