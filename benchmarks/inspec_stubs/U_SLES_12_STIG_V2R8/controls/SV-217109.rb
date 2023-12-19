control 'SV-217109' do
  title 'The SUSE operating system must initiate a session lock after a 15-minute period of inactivity for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. 

Rather than relying on the users to manually lock their SUSE operating system session prior to vacating the vicinity, the SUSE operating system needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the SUSE operating system initiates a session lock after a 15-minute period of inactivity via the graphical user interface by running the following command:

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

> sudo gsettings get org.gnome.desktop.session idle-delay

uint32 900

If the command does not return a value less than or equal to "900", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system initiates a session lock after a 15-minute period of inactivity via the graphical user interface by running the following command:

Note: This command must be run from an X11 session, otherwise the command will not work correctly.

> sudo gsettings set org.gnome.desktop.session idle-delay 900'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18337r646682_chk'
  tag severity: 'medium'
  tag gid: 'V-217109'
  tag rid: 'SV-217109r646684_rule'
  tag stig_id: 'SLES-12-010080'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-18335r646683_fix'
  tag 'documentable'
  tag legacy: ['SV-91757', 'V-77061']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
