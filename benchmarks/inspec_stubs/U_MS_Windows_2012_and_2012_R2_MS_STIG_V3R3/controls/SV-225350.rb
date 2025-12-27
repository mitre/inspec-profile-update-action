control 'SV-225350' do
  title 'App notifications on the lock screen must be turned off.'
  desc 'App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: DisableLockScreenAppNotifications

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Turn off app notifications on the lock screen" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27049r471392_chk'
  tag severity: 'medium'
  tag gid: 'V-225350'
  tag rid: 'SV-225350r569185_rule'
  tag stig_id: 'WN12-CC-000052'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27037r471393_fix'
  tag 'documentable'
  tag legacy: ['V-36687', 'SV-51612']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
