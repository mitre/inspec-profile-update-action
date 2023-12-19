control 'SV-16597' do
  title 'Classic Logon'
  desc 'This check verifies that users will always use the classic logon screen.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\

Value Name:  LogonType

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon “Always use classic logon” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15324r1_chk'
  tag severity: 'low'
  tag gid: 'V-15680'
  tag rid: 'SV-16597r1_rule'
  tag gtitle: 'Classic Logon'
  tag fix_id: 'F-15547r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
