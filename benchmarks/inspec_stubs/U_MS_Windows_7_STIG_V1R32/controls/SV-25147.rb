control 'SV-25147' do
  title 'Enable restore points for device driver installations.'
  desc 'This check verifies that a system restore point will be created when a new device driver is installed.'
  desc 'check', 'Vista/7 - If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name:  DisableSystemRestore

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Windows 7 - Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15389r1_chk'
  tag severity: 'low'
  tag gid: 'V-15701'
  tag rid: 'SV-25147r1_rule'
  tag gtitle: 'Device Install – Drivers System Restore Point'
  tag fix_id: 'F-22911r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
