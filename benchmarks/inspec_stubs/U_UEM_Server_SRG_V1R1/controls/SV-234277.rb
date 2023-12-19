control 'SV-234277' do
  title 'The UEM server must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock, but may be at the application level where the application interface window is secured instead. 

Satisfies:FMT_SMF.1.1(2) c.8 
Reference:PP-MDM-411047"
  desc 'check', 'Verify the UEM server initiates a session lock after a 15-minute period of inactivity.

If the UEM server does not initiate a session lock after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'Configure the UEM server to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37462r613841_chk'
  tag severity: 'medium'
  tag gid: 'V-234277'
  tag rid: 'SV-234277r617355_rule'
  tag stig_id: 'SRG-APP-000003-UEM-000003'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-37427r613842_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
