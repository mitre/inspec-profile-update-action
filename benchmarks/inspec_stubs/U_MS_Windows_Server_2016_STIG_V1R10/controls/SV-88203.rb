control 'SV-88203' do
  title 'Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server.'
  desc 'Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  desc 'check', 'This applies to member servers and standalone systems, It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

Value Name:  RestrictRemoteClients

Type:  REG_DWORD
Value:  0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Procedure Call >> "Restrict Unauthenticated RPC clients" to "Enabled" with "Authenticated" selected.'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73541'
  tag rid: 'SV-88203r1_rule'
  tag stig_id: 'WN16-MS-000040'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-79983r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
