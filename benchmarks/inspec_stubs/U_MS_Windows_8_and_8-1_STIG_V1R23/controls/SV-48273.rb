control 'SV-48273' do
  title 'A screen saver must be enabled on the system.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_CURRENT_USER
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\

Value Name:  ScreenSaveActive

Type:  REG_SZ
Value:  1

Applications requiring continuous, real-time screen display (e.g., network management products) require the following and must be documented with the ISSO.
 
-The logon session does not have administrator rights.
-The display station (e.g., keyboard, monitor, etc.) is located in a controlled access area.'
  desc 'fix', 'Configure the policy value for User Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Enable Screen Saver" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44951r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36656'
  tag rid: 'SV-48273r3_rule'
  tag stig_id: 'WN08-UC-000001'
  tag gtitle: 'WINUC-000001'
  tag fix_id: 'F-41408r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
