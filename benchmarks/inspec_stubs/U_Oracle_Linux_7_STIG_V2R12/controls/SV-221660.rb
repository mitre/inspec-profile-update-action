control 'SV-221660' do
  title 'The Oracle Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to lock the operating system session manually prior to leaving the workstation, operating systems must be able to identify when a user's session has idled, and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check to see if GNOME is configured to display a screensaver after a 15 minute delay with the following command:

     # grep -i idle-delay /etc/dconf/db/local.d/*
     idle-delay=uint32 900

If the "idle-delay" setting is missing or is not set to "900" or less, this is a finding.'
  desc 'fix', 'Configure the operating system to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

     # touch /etc/dconf/db/local.d/00-screensaver

Edit /etc/dconf/db/local.d/00-screensaver and add or update the following lines:

     [org/gnome/desktop/session]
     # Set the lock time out to 900 seconds before the session is considered idle
     idle-delay=uint32 900

You must include the "uint32" along with the integer key values as shown.

Update the system databases:

     # dconf update

Users must log out and then log in again before the system-wide settings take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23375r880604_chk'
  tag severity: 'medium'
  tag gid: 'V-221660'
  tag rid: 'SV-221660r880606_rule'
  tag stig_id: 'OL07-00-010070'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-23364r880605_fix'
  tag 'documentable'
  tag legacy: ['V-99061', 'SV-108165']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
