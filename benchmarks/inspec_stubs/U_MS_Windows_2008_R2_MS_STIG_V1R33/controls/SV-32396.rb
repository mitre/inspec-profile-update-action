control 'SV-32396' do
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call -> "Restrictions for Unauthenticated RPC clients" to "Enabled" and "Authenticated".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-58017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14253'
  tag rid: 'SV-32396r2_rule'
  tag stig_id: '5.123-MS'
  tag gtitle: 'RPC - Unauthenticated RPC Clients'
  tag fix_id: 'F-62379r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
