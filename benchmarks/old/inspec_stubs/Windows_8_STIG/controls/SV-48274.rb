control 'SV-48274' do
  title 'The screen saver must be password protected.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name: ScreenSaverIsSecure

Type: REG_SZ
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Password protect the screen saver" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44952r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36657'
  tag rid: 'SV-48274r2_rule'
  tag stig_id: 'WN08-UC-000003'
  tag gtitle: 'WINUC-000003'
  tag fix_id: 'F-41409r1_fix'
  tag 'documentable'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
