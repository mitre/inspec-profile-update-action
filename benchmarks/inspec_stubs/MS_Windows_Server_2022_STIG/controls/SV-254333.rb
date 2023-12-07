control 'SV-254333' do
  title 'Windows Server 2022 must prevent the display of slide shows on the lock screen.'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.'
  desc 'check', 'Verify the registry value below. 

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> Prevent enabling lock screen slide show to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57818r848813_chk'
  tag severity: 'medium'
  tag gid: 'V-254333'
  tag rid: 'SV-254333r848815_rule'
  tag stig_id: 'WN22-CC-000010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57769r848814_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
