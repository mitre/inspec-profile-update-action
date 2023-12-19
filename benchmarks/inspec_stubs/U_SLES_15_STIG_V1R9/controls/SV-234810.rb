control 'SV-234810' do
  title 'The SUSE operating system must be able to lock the graphical user interface (GUI).'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.

'
  desc 'check', 'Verify the SUSE operating system allows the user to lock the GUI. 

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Run the following command:

> sudo gsettings get org.gnome.desktop.lockdown disable-lock-screen

If the result is "true", this is a finding.'
  desc 'fix', 'Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable. This command must be run from an X11 session; otherwise, the command will not work correctly.

Configure the SUSE operating system to allow the user to lock the GUI.

Run the following command to configure the SUSE operating system to allow the user to lock the GUI:

> sudo gsettings set org.gnome.desktop.lockdown disable-lock-screen false'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-37998r618699_chk'
  tag severity: 'medium'
  tag gid: 'V-234810'
  tag rid: 'SV-234810r622137_rule'
  tag stig_id: 'SLES-15-010100'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-37961r618700_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
