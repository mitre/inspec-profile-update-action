control 'SV-16586' do
  title 'Prohibit Internet Connection Sharing'
  desc 'This check verifies Internet Connection Sharing can not be installed and configured.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name:  NC_ShowSharedAccessUI

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections “Prohibit use of Internet Connection Sharing on your DNS domain network” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15313r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15669'
  tag rid: 'SV-16586r1_rule'
  tag gtitle: 'Prohibit Internet Connection Sharing'
  tag fix_id: 'F-15536r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
