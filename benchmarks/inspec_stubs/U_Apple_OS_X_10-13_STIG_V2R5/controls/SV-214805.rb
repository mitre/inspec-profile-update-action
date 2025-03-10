control 'SV-214805' do
  title 'The macOS system must initiate a session lock after a 15-minute period of inactivity.'
  desc "A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity. This mitigates the risk that a user might forget to manually lock the screen before stepping away from the computer.

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock."
  desc 'check', 'To check if the system has a configuration profile configured to enable the screen saver after a time-out period, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep loginWindowIdleTime

The check should return a value of "900" or less for "loginWindowIdleTime". 

If it does not, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16005r396987_chk'
  tag severity: 'medium'
  tag gid: 'V-214805'
  tag rid: 'SV-214805r609363_rule'
  tag stig_id: 'AOSX-13-000010'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-16003r396988_fix'
  tag 'documentable'
  tag legacy: ['V-81469', 'SV-96183']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
