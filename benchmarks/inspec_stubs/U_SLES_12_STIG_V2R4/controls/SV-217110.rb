control 'SV-217110' do
  title 'The SUSE operating system must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. 

Rather than relying on the users to manually lock their SUSE operating system session prior to vacating the vicinity, the SUSE operating system needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the SUSE operating system must initiate a session logout after a 15-minute period of inactivity for all connection types. 

Check the proper script exists to kill an idle session after a 15-minute period of inactivity with the following command:

# cat /etc/profile.d/autologout.sh
TMOUT=900
readonly TMOUT
export TMOUT

If the file "/etc/profile.d/autologout.sh" does not exist or the output from the function call is not the same, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to initiate a session lock after a 15-minute period of inactivity by modifying or creating (if it does not already exist) the "/etc/profile.d/autologout.sh" file and add the following lines to it:

TMOUT=900
readonly TMOUT
export TMOUT

Set the proper permissions for the "/etc/profile.d/autologout.sh" file with the following command:

# sudo chmod +x /etc/profile.d/autologout.sh'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18338r369486_chk'
  tag severity: 'medium'
  tag gid: 'V-217110'
  tag rid: 'SV-217110r603262_rule'
  tag stig_id: 'SLES-12-010090'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-18336r369487_fix'
  tag 'documentable'
  tag legacy: ['V-77063', 'SV-91759']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
