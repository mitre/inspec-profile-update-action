control 'SV-224946' do
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26637r465740_chk'
  tag severity: 'medium'
  tag gid: 'V-224946'
  tag rid: 'SV-224946r852333_rule'
  tag stig_id: 'WN16-CC-000390'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-26625r465741_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00156']
  tag 'documentable'
  tag legacy: ['SV-88235', 'V-73571']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
