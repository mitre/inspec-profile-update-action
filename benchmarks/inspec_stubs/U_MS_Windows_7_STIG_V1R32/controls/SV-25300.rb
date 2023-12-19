control 'SV-25300' do
  title 'Turn off downloading of game updates.'
  desc 'This setting will prevent the system from downloading game update information from Windows Metadata Services.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\GameUX\\

Value Name:  GameUpdateOptions

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Game Explorer -> “Turn off game updates” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26860r1_chk'
  tag severity: 'low'
  tag gid: 'V-21974'
  tag rid: 'SV-25300r1_rule'
  tag gtitle: 'Turn Off Game Updates'
  tag fix_id: 'F-22964r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
