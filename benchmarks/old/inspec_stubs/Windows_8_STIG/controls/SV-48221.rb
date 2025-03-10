control 'SV-48221' do
  title 'Network Bridges must be prohibited in Windows.'
  desc 'A Network Bridge can connect two or more network segments allowing unauthorized access or exposure of sensitive data.  This setting prevents a Network Bridge from being installed and configured.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_AllowNetBridge_NLA

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44900r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15667'
  tag rid: 'SV-48221r1_rule'
  tag stig_id: 'WN08-CC-000004'
  tag gtitle: 'Prohibit Network Bridge'
  tag fix_id: 'F-41357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
