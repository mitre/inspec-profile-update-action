control 'SV-221664' do
  title 'The Oracle Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems must be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check for the session lock settings with the following commands:

     # grep -i idle-activation-enabled /etc/dconf/db/local.d/*
     idle-activation-enabled=true

If "idle-activation-enabled" is not set to "true", this is a finding.'
  desc 'fix', 'Configure the operating system to initiate a session lock after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 

     # touch /etc/dconf/db/local.d/00-screensaver

Add the setting to enable screensaver locking after 15 minutes of inactivity:

     [org/gnome/desktop/screensaver]
     idle-activation-enabled=true

Update the system databases:

     # dconf update

Users must log out and back in again before the system-wide settings take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36267r880616_chk'
  tag severity: 'medium'
  tag gid: 'V-221664'
  tag rid: 'SV-221664r880618_rule'
  tag stig_id: 'OL07-00-010100'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-36231r880617_fix'
  tag 'documentable'
  tag legacy: ['SV-108173', 'V-99069']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
