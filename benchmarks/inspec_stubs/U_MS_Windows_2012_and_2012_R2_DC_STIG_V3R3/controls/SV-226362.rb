control 'SV-226362' do
  title 'Toast notifications to the lock screen must be turned off.'
  desc 'Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

Value Name: NoToastApplicationNotificationOnLockScreen

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off toast notifications on the lock screen" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28064r476930_chk'
  tag severity: 'low'
  tag gid: 'V-226362'
  tag rid: 'SV-226362r794637_rule'
  tag stig_id: 'WN12-UC-000006'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-28052r476931_fix'
  tag 'documentable'
  tag legacy: ['SV-51763', 'V-36777']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
