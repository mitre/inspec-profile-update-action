control 'SV-225356' do
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call -> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27055r471410_chk'
  tag severity: 'medium'
  tag gid: 'V-225356'
  tag rid: 'SV-225356r877039_rule'
  tag stig_id: 'WN12-CC-000064-MS'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-27043r471411_fix'
  tag 'documentable'
  tag legacy: ['SV-52988', 'V-14253']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
