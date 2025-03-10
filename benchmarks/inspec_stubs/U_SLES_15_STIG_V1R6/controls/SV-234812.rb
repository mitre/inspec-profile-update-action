control 'SV-234812' do
  title 'The SUSE operating system must initiate a session lock after a 15-minute period of inactivity for the graphical user interface (GUI).'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. 

Rather than relying on the users to manually lock their SUSE operating system session prior to vacating the vicinity, the SUSE operating system needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the SUSE operating system initiates a session lock after a 15-minute period of inactivity via the GUI by running the following command:

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

> sudo gsettings get org.gnome.desktop.session idle-delay

uint32 900

If the command does not return a value less than or equal to "900", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to initiate a session lock after a 15-minute period of inactivity of the GUI by running the following command:

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable. This command must be run from an X11 session, otherwise the command will not work correctly.

> sudo gsettings set org.gnome.desktop.session idle-delay 900'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38000r618705_chk'
  tag severity: 'medium'
  tag gid: 'V-234812'
  tag rid: 'SV-234812r622137_rule'
  tag stig_id: 'SLES-15-010120'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-37963r618706_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
