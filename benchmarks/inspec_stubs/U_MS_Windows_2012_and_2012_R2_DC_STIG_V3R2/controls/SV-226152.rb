control 'SV-226152' do
  title 'A system restore point must be created when a new device driver is installed.'
  desc 'A system restore point allows a rollback if an issue is  encountered when a new device driver is installed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSystemRestore

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27854r475779_chk'
  tag severity: 'low'
  tag gid: 'V-226152'
  tag rid: 'SV-226152r569184_rule'
  tag stig_id: 'WN12-CC-000021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27842r475780_fix'
  tag 'documentable'
  tag legacy: ['SV-53099', 'V-15701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
