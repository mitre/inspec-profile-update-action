control 'SV-48552' do
  title 'The Remote Desktop Session Host must require secure RPC communications.'
  desc 'Allowing unsecure RPC communication exposes the system to man in the middle attacks and data disclosure attacks. A man in the middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security "Require secure RPC communication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45196r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4447'
  tag rid: 'SV-48552r1_rule'
  tag stig_id: 'WN08-CC-000130'
  tag gtitle: 'TS/RDS -  Secure RPC Connection.'
  tag fix_id: 'F-41666r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
