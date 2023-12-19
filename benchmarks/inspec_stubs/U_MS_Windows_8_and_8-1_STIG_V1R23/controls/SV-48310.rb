control 'SV-48310' do
  title 'App notifications on the lock screen must be turned off.'
  desc 'App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: DisableLockScreenAppNotifications

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Turn off app notifications on the lock screen" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36687'
  tag rid: 'SV-48310r2_rule'
  tag stig_id: 'WN08-CC-000052'
  tag gtitle: 'WINCC-000052'
  tag fix_id: 'F-41444r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
