control 'SV-16647' do
  title 'Digital Locker'
  desc 'This check verifies that Digital Locker, a dedicated download manager can not run.'
  desc 'check', 'Vista - If the following registry value doesn’t exist or its value is not set to “1”, then this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Digital Locker\\

Value Name:	DoNotRunDigitalLocker

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Digital Locker “Do not allow Digital Locker to run” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15396r1_chk'
  tag severity: 'low'
  tag gid: 'V-15708'
  tag rid: 'SV-16647r2_rule'
  tag gtitle: 'Digital Locker'
  tag fix_id: 'F-15600r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
