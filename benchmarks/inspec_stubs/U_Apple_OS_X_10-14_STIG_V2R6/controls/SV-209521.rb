control 'SV-209521' do
  title 'The macOS system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock = 0;"

If there is no result, this is a finding.'
  desc 'fix', 'This setting is enforced using the “Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9772r282045_chk'
  tag severity: 'medium'
  tag gid: 'V-209521'
  tag rid: 'SV-209521r610285_rule'
  tag stig_id: 'AOSX-14-000001'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-9772r282046_fix'
  tag 'documentable'
  tag legacy: ['SV-104925', 'V-95787']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
