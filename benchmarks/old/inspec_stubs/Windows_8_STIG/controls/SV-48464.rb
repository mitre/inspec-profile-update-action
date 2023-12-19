control 'SV-48464' do
  title 'Notifications from Windows Push Network Service must be turned off.'
  desc 'The Windows Push Notification Service (WNS) allows third-party vendors to send updates for toasts, tiles, and badges.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

Value Name: NoCloudApplicationNotification

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off notifications network usage" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45127r1_chk'
  tag severity: 'low'
  tag gid: 'V-36776'
  tag rid: 'SV-48464r2_rule'
  tag stig_id: 'WN08-UC-000005'
  tag gtitle: 'WINUC-000005'
  tag fix_id: 'F-41590r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
