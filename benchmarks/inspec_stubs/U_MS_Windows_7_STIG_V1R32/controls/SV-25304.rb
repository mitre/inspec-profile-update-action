control 'SV-25304' do
  title 'Windows Anytime Upgrade is not disabled.'
  desc 'This setting will prevent Windows Anytime Upgrade from running.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\WAU\\

Value Name:  Disabled

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Anytime Upgrade -> “Prevent Windows Anytime Upgrade from running” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26863r1_chk'
  tag severity: 'low'
  tag gid: 'V-21978'
  tag rid: 'SV-25304r1_rule'
  tag gtitle: 'Windows Anytime Upgrade'
  tag fix_id: 'F-22970r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
