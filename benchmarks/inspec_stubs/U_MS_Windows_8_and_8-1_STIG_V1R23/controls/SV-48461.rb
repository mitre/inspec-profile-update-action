control 'SV-48461' do
  title 'A screen saver must be defined.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Specifying a screen saver ensures the screen saver timeout lock is initiated properly.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name: SCRNSAVE.EXE

Type: REG_SZ
Value: scrnsave.scr'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Force specific screen saver" to "Enabled" with "scrnsave.scr" specified as the Screen saver executable name.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45125r1_chk'
  tag severity: 'low'
  tag gid: 'V-36774'
  tag rid: 'SV-48461r2_rule'
  tag stig_id: 'WN08-UC-000002'
  tag gtitle: 'WINUC-000002'
  tag fix_id: 'F-41588r1_fix'
  tag 'documentable'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
