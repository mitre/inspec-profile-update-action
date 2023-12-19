control 'SV-226201' do
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Always prompt for password upon connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27903r475926_chk'
  tag severity: 'medium'
  tag gid: 'V-226201'
  tag rid: 'SV-226201r794483_rule'
  tag stig_id: 'WN12-CC-000099'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-27891r475927_fix'
  tag 'documentable'
  tag legacy: ['SV-52898', 'V-3453']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
