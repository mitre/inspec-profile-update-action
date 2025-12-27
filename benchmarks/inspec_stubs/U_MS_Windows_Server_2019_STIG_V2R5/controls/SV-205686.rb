control 'SV-205686' do
  title 'Windows Server 2019 must prevent the display of slide shows on the lock screen.'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.'
  desc 'check', 'Verify the registry value below. 

If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen slide show" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5951r354976_chk'
  tag severity: 'medium'
  tag gid: 'V-205686'
  tag rid: 'SV-205686r569188_rule'
  tag stig_id: 'WN19-CC-000010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5951r354977_fix'
  tag 'documentable'
  tag legacy: ['V-93399', 'SV-103485']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
