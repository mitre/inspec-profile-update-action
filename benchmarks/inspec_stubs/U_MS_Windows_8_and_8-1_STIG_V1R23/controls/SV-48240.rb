control 'SV-48240' do
  title 'A system restore point must be created when a new device driver is installed.'
  desc 'A system restore point allows a rollback if an issue is  encountered when a new device driver is installed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSystemRestore

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44919r1_chk'
  tag severity: 'low'
  tag gid: 'V-15701'
  tag rid: 'SV-48240r2_rule'
  tag stig_id: 'WN08-CC-000021'
  tag gtitle: 'Device Install – Drivers System Restore Point'
  tag fix_id: 'F-41376r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
