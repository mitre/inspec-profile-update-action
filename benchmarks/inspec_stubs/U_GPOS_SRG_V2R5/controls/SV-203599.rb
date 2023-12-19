control 'SV-203599' do
  title 'The operating system must initiate a session lock after a 15-minute period of inactivity for all connection types.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the operating system initiates a session lock after a 15-minute period of inactivity for all connection types. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to initiate a session lock after a 15-minute period of inactivity for all connection types.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3724r557053_chk'
  tag severity: 'medium'
  tag gid: 'V-203599'
  tag rid: 'SV-203599r557055_rule'
  tag stig_id: 'SRG-OS-000029-GPOS-00010'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-3724r557054_fix'
  tag 'documentable'
  tag legacy: ['V-56633', 'SV-70893']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
