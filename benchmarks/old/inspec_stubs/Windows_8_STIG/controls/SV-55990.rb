control 'SV-55990' do
  title 'Camera access from the lock screen must be disabled.'
  desc 'Enabling camera access from the lock screen could allow for unauthorized use.  Requiring logon will ensure the device is only used by authorized personnel.'
  desc 'check', 'If the device does not have a camera, this is NA.

Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenCamera

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen camera" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43237'
  tag rid: 'SV-55990r3_rule'
  tag stig_id: 'WN08-CC-000137'
  tag gtitle: 'WINCC-000137'
  tag fix_id: 'F-71647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
