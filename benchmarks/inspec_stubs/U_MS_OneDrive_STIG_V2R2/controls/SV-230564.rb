control 'SV-230564' do
  title 'The use of personal accounts for OneDrive synchronization must be disabled.'
  desc 'OneDrive provides access to external services for data storage, which must be restricted to authorized instances. Enabling this setting will prevent the use of personal OneDrive accounts for synchronization.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Policies\\Microsoft\\OneDrive\\

Value Name: DisablePersonalSync

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for User Configuration >> Administrative Templates >> OneDrive >> "Prevent users from synchronizing personal OneDrive accounts" to "Enabled".   

Group policy files for OneDrive are located on a system with OneDrive in "%localappdata%\\Microsoft\\OneDrive\\BuildNumber\\adm\\".

Copy the OneDrive.admx and .adml files to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive for Business 2016'
  tag check_id: 'C-33233r603123_chk'
  tag severity: 'medium'
  tag gid: 'V-230564'
  tag rid: 'SV-230564r569322_rule'
  tag stig_id: 'DTOO607'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-33208r603124_fix'
  tag 'documentable'
  tag legacy: ['V-82137', 'SV-96851']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
