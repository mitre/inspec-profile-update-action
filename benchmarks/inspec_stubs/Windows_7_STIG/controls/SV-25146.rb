control 'SV-25146' do
  title 'A Windows error report is not sent when a generic driver is installed.'
  desc 'This check verifies that an error report will not be sent when a generic device driver is installed.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name:  DisableSendGenericDriverNotFoundToWER

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Windows 7 - Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Do not send a Windows Error Report when a generic driver is installed on a device” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15390r1_chk'
  tag severity: 'low'
  tag gid: 'V-15702'
  tag rid: 'SV-25146r1_rule'
  tag gtitle: 'Device Install – Generic Driver Error Report'
  tag fix_id: 'F-22910r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
