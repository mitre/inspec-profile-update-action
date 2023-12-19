control 'SV-25141' do
  title 'Prohibit Network Bridge in Windows.'
  desc 'This check verifies the Network Bridge cannot be installed and configured.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name:  NC_AllowNetBridge_NLA

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections “Prohibit installation and configuration of Network Bridge on your DNS domain network” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15667'
  tag rid: 'SV-25141r1_rule'
  tag gtitle: 'Prohibit Network Bridge'
  tag fix_id: 'F-15533r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
