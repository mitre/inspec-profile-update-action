control 'SV-226360' do
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
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28062r476924_chk'
  tag severity: 'medium'
  tag gid: 'V-226360'
  tag rid: 'SV-226360r794619_rule'
  tag stig_id: 'WN12-UC-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-28050r476925_fix'
  tag 'documentable'
  tag legacy: ['SV-51760', 'V-36657']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
