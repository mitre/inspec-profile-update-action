control 'SV-36284' do
  title 'Windows will be prevented from sending an error report when a device driver requests additional software during installation.'
  desc 'Sending error reports to vendors can disclose information about a system to an outside organization.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSendRequestAdditionalSoftwareToWER

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> “Prevent Windows from sending an error report when a device driver requests additional software during installation” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-35392r1_chk'
  tag severity: 'low'
  tag gid: 'V-28504'
  tag rid: 'SV-36284r1_rule'
  tag gtitle: 'Device Install Software Request Error Report'
  tag fix_id: 'F-30621r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
