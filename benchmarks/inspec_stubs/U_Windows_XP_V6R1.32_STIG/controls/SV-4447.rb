control 'SV-4447' do
  title 'The Terminal Server does not require secure RPC communication.'
  desc 'Allowing unsecure RPC communication exposes the server to man in  the middle attacks and data disclosure attacks. A man in the middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ 

Value Name: fEncryptRPCTraffic 

Type: REG_DWORD Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Encryption and Security -> RPC Security Policy “Secure Server (Require Security)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4447'
  tag rid: 'SV-4447r1_rule'
  tag gtitle: 'TS/RDS -  Secure RPC Connection.'
  tag fix_id: 'F-5938r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
