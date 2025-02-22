control 'SV-207347' do
  title 'The VMM must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the VMM but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their VMM session prior to vacating the vicinity, VMMs need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the VMM initiates a session lock after a 15-minute period of inactivity. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7604r365451_chk'
  tag severity: 'medium'
  tag gid: 'V-207347'
  tag rid: 'SV-207347r378598_rule'
  tag stig_id: 'SRG-OS-000029-VMM-000100'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-7604r365452_fix'
  tag 'documentable'
  tag legacy: ['SV-71119', 'V-56859']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
