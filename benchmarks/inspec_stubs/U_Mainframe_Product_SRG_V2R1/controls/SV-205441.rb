control 'SV-205441' do
  title 'The Mainframe Product must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead."
  desc 'check', 'If the Mainframe Product has no data screen capability, this requirement is not applicable.

Examine configuration parameters to determine whether the Mainframe Product performs a session lock after 15 minutes of inactivity. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to perform a session lock after 15 minutes of inactivity.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5707r299556_chk'
  tag severity: 'medium'
  tag gid: 'V-205441'
  tag rid: 'SV-205441r395448_rule'
  tag stig_id: 'SRG-APP-000003-MFP-000003'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-5707r299557_fix'
  tag 'documentable'
  tag legacy: ['SV-82601', 'V-68111']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
