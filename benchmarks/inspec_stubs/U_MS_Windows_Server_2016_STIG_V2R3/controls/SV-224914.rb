control 'SV-224914' do
  title 'The display of slide shows on the lock screen must be disabled.'
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
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26605r465644_chk'
  tag severity: 'medium'
  tag gid: 'V-224914'
  tag rid: 'SV-224914r569186_rule'
  tag stig_id: 'WN16-CC-000010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26593r465645_fix'
  tag 'documentable'
  tag legacy: ['SV-88145', 'V-73493']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
