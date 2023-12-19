control 'SV-80349' do
  title 'Trend Deep Security must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead."
  desc 'check', 'Review the Trend Deep Security server configuration to ensure a session lock is initiated after a 15-minute period of inactivity.

Review the application System Settings, to ensure the system timeout is set to 15 minutes or less. 

If the timeout session is not set to 15 minutes or less this is a finding. 

Administration >> System Settings >> Security >> User Security >> Session Timeout: 10 Minutes'
  desc 'fix', 'Configure the Trend Deep Security server to initiate a session lock after a 15-minute period of inactivity.

Set the Session Timeout to 15 minutes or less.

Administration >> Security >> User Security >> Session Timeout: 10 Minutes'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65859'
  tag rid: 'SV-80349r1_rule'
  tag stig_id: 'TMDS-00-000010'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-71935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
