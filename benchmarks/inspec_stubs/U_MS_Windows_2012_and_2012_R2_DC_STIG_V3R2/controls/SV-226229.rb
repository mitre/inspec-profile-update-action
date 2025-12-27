control 'SV-226229' do
  title 'The display of slide shows on the lock screen must be disabled (Windows 2012 R2).'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Prevent enabling lock screen slide show" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27931r476531_chk'
  tag severity: 'medium'
  tag gid: 'V-226229'
  tag rid: 'SV-226229r569184_rule'
  tag stig_id: 'WN12-CC-000138'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27919r476532_fix'
  tag 'documentable'
  tag legacy: ['V-43238', 'SV-56343']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
