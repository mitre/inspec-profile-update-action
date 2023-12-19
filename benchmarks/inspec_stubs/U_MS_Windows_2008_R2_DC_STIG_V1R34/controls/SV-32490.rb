control 'SV-32490' do
  title 'Remote Desktop Services will always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their Remote Desktop session.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the host.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fPromptForPassword

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> “Always prompt for password upon connection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-1880r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3453'
  tag rid: 'SV-32490r1_rule'
  tag gtitle: 'TS/RDS - Password Prompting'
  tag fix_id: 'F-28877r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
