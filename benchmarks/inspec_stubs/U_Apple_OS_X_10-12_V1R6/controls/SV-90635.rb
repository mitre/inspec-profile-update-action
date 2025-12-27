control 'SV-90635' do
  title 'The OS X system must be configured to disable hot corners.'
  desc "Although hot comers can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock."
  desc 'check', %q(To check if the system is configured to disable hot corners, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep '"wvous-bl-corner = 0;"'
/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep '"wvous-tl-corner = 0;"'
/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep '"wvous-br-corner = 0;"'
/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep '"wvous-tr-corner = 0;"'

If any of the commands returns no result, this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75629r2_chk'
  tag severity: 'medium'
  tag gid: 'V-75947'
  tag rid: 'SV-90635r2_rule'
  tag stig_id: 'AOSX-12-000006'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-82585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
