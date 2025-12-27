control 'SV-25201' do
  title 'The system must be configured with a password-protected screen saver.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If any of the registry values do not exist or are not configured as follows, this is a finding:

Registry Hive:  HKEY_CURRENT_USER
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name:  ScreenSaveActive
Value Type:  REG_SZ
Value:  1

Value Name:  ScreenSaverIsSecure
Value Type:  REG_SZ
Value:  1

Value Name:  ScreenSaveTimeout
Value Type:  REG_SZ
Value:  900 (or less)

Applications requiring continuous, real-time screen display (e.g., network management products) require the following and must be documented with the ISSO.

-The logon session does not have administrator rights.
-The display station (e.g., keyboard, monitor, etc.) is located in a controlled access area.'
  desc 'fix', 'Configure the policy values for User Configuration >> Administrative Templates >> Control Panel >> Personalization >> as follows:

"Enable Screen Saver" to "Enabled".
"Password protect the screen saver" to "Enabled".
"Screen Saver timeout" to "Enabled: 900 seconds" (or less).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62055r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1122'
  tag rid: 'SV-25201r2_rule'
  tag gtitle: 'Password Protected Screen Saver'
  tag fix_id: 'F-66953r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000056', 'CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
