control 'SV-32472' do
  title 'An Error Report will not be sent when a generic device driver is installed.'
  desc 'This check verifies that an Error Report will not be sent when a generic device driver is installed.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\ 

Value Name: DisableSendGenericDriverNotFoundToWER 

Type: REG_DWORD 
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Do not send a Windows error report when a generic driver is installed on a device” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32789r1_chk'
  tag severity: 'low'
  tag gid: 'V-15702'
  tag rid: 'SV-32472r1_rule'
  tag gtitle: 'Device Install – Generic Driver Error Report'
  tag fix_id: 'F-28865r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
