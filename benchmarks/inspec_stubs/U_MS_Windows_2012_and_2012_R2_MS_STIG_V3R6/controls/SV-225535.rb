control 'SV-225535' do
  title 'The screen saver must be password protected.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name: ScreenSaverIsSecure

Type: REG_SZ
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Password protect the screen saver" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27234r471947_chk'
  tag severity: 'medium'
  tag gid: 'V-225535'
  tag rid: 'SV-225535r569185_rule'
  tag stig_id: 'WN12-UC-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-27222r471948_fix'
  tag 'documentable'
  tag legacy: ['SV-51760', 'V-36657']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
