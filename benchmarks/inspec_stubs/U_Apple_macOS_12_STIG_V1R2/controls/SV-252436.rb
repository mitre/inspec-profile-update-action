control 'SV-252436' do
  title 'The macOS system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock"

allowAutoUnlock = 0;

If there is no result or "allowAutoUnlock" is not set to "0", this is a finding.'
  desc 'fix', 'This setting is enforced using the “Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55892r816120_chk'
  tag severity: 'medium'
  tag gid: 'V-252436'
  tag rid: 'SV-252436r816122_rule'
  tag stig_id: 'APPL-12-000001'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-55842r816121_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
