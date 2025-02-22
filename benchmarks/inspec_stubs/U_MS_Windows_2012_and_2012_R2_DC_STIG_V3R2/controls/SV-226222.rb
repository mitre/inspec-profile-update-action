control 'SV-226222' do
  title 'The Remote Desktop Session Host must require secure RPC communications.'
  desc 'Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks.  A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged.  Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Require secure RPC communication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27924r475989_chk'
  tag severity: 'medium'
  tag gid: 'V-226222'
  tag rid: 'SV-226222r569184_rule'
  tag stig_id: 'WN12-CC-000130'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-27912r475990_fix'
  tag 'documentable'
  tag legacy: ['SV-52932', 'V-4447']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
