control 'SV-32294' do
  title 'The system will be configured with a password-protected screen saver.'
  desc 'The system should be locked when unattended.  Unattended systems are susceptible to unauthorized use.  The screen saver should be set at a maximum of 15 minutes and password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If any of the registry values don’t exist or are not configured as follows, then this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name:  ScreenSaveActive
Type: REG_SZ
Value: 1

Value Name:  ScreenSaverIsSecure
Type: REG_SZ
Value: 1

Value Name:  ScreenSaveTimeOut
Type: REG_SZ
Value: 900 (or less)

Documentable Explanation:  Terminal servers and applications requiring continuous, real-time screen display (i.e., network management products) require the following and need to be documented with the IAO.
 
-The logon session does not have administrator rights. 
-The display station (i.e., keyboard, monitor, etc.) is located in a controlled access area.'
  desc 'fix', 'Configure the policy values for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> as follows:

“Enable Screen Saver” will be set to “Enabled”.
“Password protect the screen saver” will be set to “Enabled”.
“Screen Saver timeout” will be set to “Enabled: 900 seconds” (or less).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1122'
  tag rid: 'SV-32294r1_rule'
  tag gtitle: 'Password Protected Screen Saver'
  tag fix_id: 'F-28808r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000056', 'CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
