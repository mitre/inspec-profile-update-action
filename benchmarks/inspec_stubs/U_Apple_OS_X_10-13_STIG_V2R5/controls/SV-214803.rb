control 'SV-214803' do
  title 'The macOS system must be configured to disable hot corners.'
  desc "Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock."
  desc 'check', 'To check if the system is configured to disable hot corners, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous

If the return is null, or does not equal:
"wvous-bl-corner = 0;
wvous-br-corner = 0;
wvous-tl-corner = 0;
wvous-tr-corner = 0;" 
this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16003r396981_chk'
  tag severity: 'medium'
  tag gid: 'V-214803'
  tag rid: 'SV-214803r609363_rule'
  tag stig_id: 'AOSX-13-000006'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-16001r396982_fix'
  tag 'documentable'
  tag legacy: ['V-81465', 'SV-96179']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
