control 'SV-55991' do
  title 'The display of slide shows on the lock screen must be disabled.'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen slide show" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43238'
  tag rid: 'SV-55991r3_rule'
  tag stig_id: 'WN08-CC-000138'
  tag gtitle: 'WINCC-000138'
  tag fix_id: 'F-71649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
