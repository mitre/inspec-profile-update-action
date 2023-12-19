control 'SV-217107' do
  title 'The SUSE operating system must be able to lock the graphical user interface (GUI).'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.

'
  desc 'check', 'Verify the SUSE operating system allows the user to lock the GUI. 

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable. This command must be run from an X11 session, otherwise the command will not work correctly.

Run the following command:

# gsettings get org.gnome.desktop.lockdown disable-lock-screen

If the result is "true", this is a finding.'
  desc 'fix', 'This command must be run from an X11 session; otherwise, the command will not work correctly.

Configure the SUSE operating system to allow the user to lock the graphical user interface.

Run the following command to configure the SUSE operating system to allow the user to lock the graphical user interface:

# gsettings set org.gnome.desktop.lockdown disable-lock-screen false'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18335r369477_chk'
  tag severity: 'medium'
  tag gid: 'V-217107'
  tag rid: 'SV-217107r603262_rule'
  tag stig_id: 'SLES-12-010060'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-18333r369478_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag legacy: ['SV-91753', 'V-77057']
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
