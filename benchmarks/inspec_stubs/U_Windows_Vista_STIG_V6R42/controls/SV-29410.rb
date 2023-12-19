control 'SV-29410' do
  title 'Client computers required to authenticate for RPC communication.'
  desc 'This check verifies that the system is configured to force client computers to provide authentication before an RPC communication is established.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name:  EnableAuthEpResolution

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call “RPC Endpoint Mapper Client Authentication” to “Enabled.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11600r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14254'
  tag rid: 'SV-29410r1_rule'
  tag gtitle: 'RPC - Endpoint Mapper Authentication'
  tag fix_id: 'F-13579r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
