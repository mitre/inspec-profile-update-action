control 'SV-48207' do
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name: RestrictRemoteClients

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call -> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44886r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14253'
  tag rid: 'SV-48207r1_rule'
  tag stig_id: 'WN08-CC-000064'
  tag gtitle: 'RPC - Unauthenticated RPC Clients'
  tag fix_id: 'F-41343r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
