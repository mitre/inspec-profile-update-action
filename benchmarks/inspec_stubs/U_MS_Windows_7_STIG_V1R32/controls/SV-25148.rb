control 'SV-25148' do
  title 'Users will not be prompted to search Windows Update for device drivers.'
  desc 'This check verifies that users will not be prompted to search Windows Updated for device drivers.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name:  DontPromptForWindowsUpdate

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation “Turn off Windows Update device driver search prompt” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15391r1_chk'
  tag severity: 'low'
  tag gid: 'V-15703'
  tag rid: 'SV-25148r1_rule'
  tag gtitle: 'Driver Install – Device Driver Search Prompt'
  tag fix_id: 'F-15595r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
