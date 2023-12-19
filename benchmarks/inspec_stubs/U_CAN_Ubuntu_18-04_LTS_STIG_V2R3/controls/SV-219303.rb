control 'SV-219303' do
  title 'The Ubuntu operating system must initiate a session lock after a 15-minute period of inactivity for all connection types.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the Ubuntu operating system need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the Ubuntu operating system initiates a session logout after a 15-minute period of inactivity. 

Check that the proper auto logout script exists with the following command:

# cat /etc/profile.d/autologout.sh
TMOUT=900
readonly TMOUT
export TMOUT

If the file "/etc/profile.d/autologout.sh" does not exist with the contents shown above, the value of "TMOUT" is greater than 900, or the timeout values are commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to initiate a session logout after a 15-minute period of inactivity. 

Create a file to contain the system-wide session auto logout script (if it does not already exist) with the following command:

# sudo touch /etc/profile.d/autologout.sh

Add the following lines to the "/etc/profile.d/autologout.sh" script:

TMOUT=900
readonly TMOUT
export TMOUT'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21028r305237_chk'
  tag severity: 'medium'
  tag gid: 'V-219303'
  tag rid: 'SV-219303r610963_rule'
  tag stig_id: 'UBTU-18-010402'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-21027r305238_fix'
  tag 'documentable'
  tag legacy: ['SV-109933', 'V-100829']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
