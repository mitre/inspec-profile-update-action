control 'SV-254368' do
  title 'Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.'
  desc 'Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> Require secure RPC communication to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57853r848918_chk'
  tag severity: 'medium'
  tag gid: 'V-254368'
  tag rid: 'SV-254368r877398_rule'
  tag stig_id: 'WN22-CC-000370'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-57804r848919_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000250-GPOS-00093']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
