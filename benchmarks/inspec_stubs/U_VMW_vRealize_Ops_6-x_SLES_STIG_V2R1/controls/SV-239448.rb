control 'SV-239448' do
  title 'The SLES for vRealize must initiate a session lock after a 15-minute period of inactivity for all connection types.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, SLES for vRealize needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Check for the existence of the /etc/profile.d/tmout.sh file:

# ls -al /etc/profile.d/tmout.sh

Check for the presence of the "TMOUT" variable:

# grep TMOUT /etc/profile.d/tmout.sh

The value of "TMOUT" should be set to 900 seconds (15 minutes).

If the file does not exist, or the "TMOUT" variable is not set, this is a finding.'
  desc 'fix', 'Ensure the file exists and is owned by root. If the files does not exist, use the following commands to create the file:

# touch /etc/profile.d/tmout.sh
# chown root:root /etc/profile.d/tmout.sh
# chmod 644 /etc/profile.d/tmout.sh

Edit the file "/etc/profile.d/tmout.sh", and add the following lines: 

TMOUT=900
readonly TMOUT
export TMOUT
mesg n 2>/dev/null'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42681r661793_chk'
  tag severity: 'medium'
  tag gid: 'V-239448'
  tag rid: 'SV-239448r661795_rule'
  tag stig_id: 'VROM-SL-000050'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-42640r661794_fix'
  tag 'documentable'
  tag legacy: ['SV-99017', 'V-88367']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
