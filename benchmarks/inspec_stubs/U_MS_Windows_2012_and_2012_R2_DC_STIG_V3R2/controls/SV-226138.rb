control 'SV-226138' do
  title 'Network Bridges must be prohibited in Windows.'
  desc 'A Network Bridge can connect two or more network segments, allowing unauthorized access or exposure of sensitive data.  This setting prevents a Network Bridge from being installed and configured.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_AllowNetBridge_NLA

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27840r475737_chk'
  tag severity: 'medium'
  tag gid: 'V-226138'
  tag rid: 'SV-226138r569184_rule'
  tag stig_id: 'WN12-CC-000004'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27828r475738_fix'
  tag 'documentable'
  tag legacy: ['V-15667', 'SV-53014']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
