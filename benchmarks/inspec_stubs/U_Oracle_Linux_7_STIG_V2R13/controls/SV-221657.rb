control 'SV-221657' do
  title 'The Oracle Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.

'
  desc 'check', %q(Verify the operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check to see if the screen lock is enabled with the following command:

     # grep -i lock-enabled /etc/dconf/db/local.d/*
     lock-enabled=true

If the "lock-enabled" setting is missing or is not set to "true", this is a finding.)
  desc 'fix', %q(Configure the operating system to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

     # touch /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

     # Set this to true to lock the screen when the screensaver activates
     lock-enabled=true

Update the system databases:

     # dconf update

Users must log out and then log in again before the system-wide settings take effect.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23372r880598_chk'
  tag severity: 'medium'
  tag gid: 'V-221657'
  tag rid: 'SV-221657r880600_rule'
  tag stig_id: 'OL07-00-010060'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-23361r880599_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag legacy: ['SV-108159', 'V-99055']
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
