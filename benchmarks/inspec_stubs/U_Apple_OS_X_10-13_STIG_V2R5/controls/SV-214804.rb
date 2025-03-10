control 'SV-214804' do
  title 'The macOS system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock = 0;"

If there is no result, this is a finding.'
  desc 'fix', 'This setting is enforced using the “Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16004r396984_chk'
  tag severity: 'medium'
  tag gid: 'V-214804'
  tag rid: 'SV-214804r609363_rule'
  tag stig_id: 'AOSX-13-000007'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-16002r396985_fix'
  tag 'documentable'
  tag legacy: ['V-81467', 'SV-96181']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
