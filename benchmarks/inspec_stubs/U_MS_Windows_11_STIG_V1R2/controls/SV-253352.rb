control 'SV-253352' do
  title 'The display of slide shows on the lock screen must be disabled.'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen slide show" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56805r829138_chk'
  tag severity: 'medium'
  tag gid: 'V-253352'
  tag rid: 'SV-253352r829140_rule'
  tag stig_id: 'WN11-CC-000010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56755r829139_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
