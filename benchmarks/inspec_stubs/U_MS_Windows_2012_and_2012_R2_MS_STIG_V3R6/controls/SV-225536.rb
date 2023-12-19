control 'SV-225536' do
  title 'Notifications from Windows Push Network Service must be turned off.'
  desc 'The Windows Push Notification Service (WNS) allows third-party vendors to send updates for toasts, tiles, and badges.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

Value Name: NoCloudApplicationNotification

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off notifications network usage" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27235r471950_chk'
  tag severity: 'low'
  tag gid: 'V-225536'
  tag rid: 'SV-225536r569185_rule'
  tag stig_id: 'WN12-UC-000005'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27223r471951_fix'
  tag 'documentable'
  tag legacy: ['SV-51762', 'V-36776']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
