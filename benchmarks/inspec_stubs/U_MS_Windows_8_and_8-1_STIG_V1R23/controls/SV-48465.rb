control 'SV-48465' do
  title 'Toast notifications to the lock screen must be turned off.'
  desc 'Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

Value Name: NoToastApplicationNotificationOnLockScreen

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off toast notifications on the lock screen" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45129r1_chk'
  tag severity: 'low'
  tag gid: 'V-36777'
  tag rid: 'SV-48465r2_rule'
  tag stig_id: 'WN08-UC-000006'
  tag gtitle: 'WINUC-000006'
  tag fix_id: 'F-41592r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
