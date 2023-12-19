control 'SV-257142' do
  title 'The macOS system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'Verify the macOS system is configured to prevent Apple Watch from terminating a session lock with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock"

allowAutoUnlock = 0;

If there is no result or "allowAutoUnlock" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the macOS system to prevent Apple Watch from terminating a session lock by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60827r905057_chk'
  tag severity: 'medium'
  tag gid: 'V-257142'
  tag rid: 'SV-257142r905059_rule'
  tag stig_id: 'APPL-13-000001'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-60768r905058_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
