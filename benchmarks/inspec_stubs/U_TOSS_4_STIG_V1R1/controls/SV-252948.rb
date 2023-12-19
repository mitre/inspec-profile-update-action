control 'SV-252948' do
  title "TOSS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock shall remain in place until the user re-authenticates. No other activity aside from re-authentication shall unlock the system.

'
  desc 'check', %q(Verify TOSS retains a user's session lock until that user reestablishes access using established identification and authentication procedures with the following command:

Note: This requirement assumes the use of the TOSS default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.desktop.screensaver lock-enabled
true

If the setting is "false", this is a finding.)
  desc 'fix', %q(Configure TOSS to retain a user's session lock until that user reestablishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true

Update the system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56401r824166_chk'
  tag severity: 'medium'
  tag gid: 'V-252948'
  tag rid: 'SV-252948r824168_rule'
  tag stig_id: 'TOSS-04-020020'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-56351r824167_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
