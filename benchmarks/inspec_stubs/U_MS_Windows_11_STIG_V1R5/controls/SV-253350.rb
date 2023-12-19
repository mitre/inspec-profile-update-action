control 'SV-253350' do
  title 'Camera access from the lock screen must be disabled.'
  desc 'Enabling camera access from the lock screen could allow for unauthorized use. Requiring logon will ensure the device is only used by authorized personnel.'
  desc 'check', 'If the device does not have a camera, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenCamera

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'If the device does not have a camera, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen camera" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56803r829132_chk'
  tag severity: 'medium'
  tag gid: 'V-253350'
  tag rid: 'SV-253350r829134_rule'
  tag stig_id: 'WN11-CC-000005'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56753r829133_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
