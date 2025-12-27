control 'SV-90637' do
  title 'The OS X system must be configured to prevent Apple Watch from terminating a session lock.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock = 0;"

If there is no result, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Security Privacy Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75949'
  tag rid: 'SV-90637r1_rule'
  tag stig_id: 'AOSX-12-000007'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-82587r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
