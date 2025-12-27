control 'SV-257145' do
  title 'The macOS system must initiate a session lock after a 15-minute period of inactivity.'
  desc "A screen saver must be enabled and set to require a password to unlock. The timeout must be set to 15 minutes of inactivity. This mitigates the risk that a user might forget to manually lock the screen before stepping away from the computer.

A session timeout lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock."
  desc 'check', 'Verify the macOS system is configured to initiate the screen saver after 15 minutes of inactivity with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "loginWindowIdleTime"

loginWindowIdleTime = 900;

If there is no result, or if "idleTime" is not set to "900" seconds or less, this is a finding.'
  desc 'fix', 'Configure the macOS system to initiate the screen saver after 15 minutes of inactivity by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60830r905066_chk'
  tag severity: 'medium'
  tag gid: 'V-257145'
  tag rid: 'SV-257145r905068_rule'
  tag stig_id: 'APPL-13-000004'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-60771r905067_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
