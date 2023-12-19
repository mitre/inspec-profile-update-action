control 'SV-48088' do
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fPromptForPassword

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Always prompt for password upon connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44827r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3453'
  tag rid: 'SV-48088r1_rule'
  tag stig_id: 'WN08-CC-000099'
  tag gtitle: 'TS/RDS - Password Prompting'
  tag fix_id: 'F-41225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
