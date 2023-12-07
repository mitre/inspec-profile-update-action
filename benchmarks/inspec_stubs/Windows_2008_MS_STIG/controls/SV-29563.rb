control 'SV-29563' do
  title 'Network – Windows Connect Now Wizards'
  desc 'This check verifies that access to the Windows Connect Now wizards is disabled.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\WCN\\UI\\

Value Name:  DisableWcnUi

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now “Prohibit Access of the Windows Connect Now wizards” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15387r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15699'
  tag rid: 'SV-29563r1_rule'
  tag gtitle: 'Network – Windows Connect Now Wizards'
  tag fix_id: 'F-15591r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
