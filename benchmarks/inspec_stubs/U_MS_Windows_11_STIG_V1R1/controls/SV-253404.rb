control 'SV-253404' do
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fPromptForPassword

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56857r829294_chk'
  tag severity: 'medium'
  tag gid: 'V-253404'
  tag rid: 'SV-253404r829296_rule'
  tag stig_id: 'WN11-CC-000280'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-56807r829295_fix'
  tag 'documentable'
  tag cci: ['CCI-002008']
  tag nist: ['IA-5 (14)']
end
