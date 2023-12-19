control 'SV-204403' do
  title 'The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface.'
  desc "A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

The ability to enable/disable a session lock is given to the user by default. Disabling the user's ability to disengage the graphical user interface session lock provides the assurance that all sessions will lock after the specified period of time."
  desc 'check', 'Verify the operating system prevents a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface. 

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:
     # grep system-db /etc/dconf/profile/user

     system-db:local

Check for the idle-activation-enabled setting with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

     # grep -i idle-activation-enabled /etc/dconf/db/local.d/locks/*

     /org/gnome/desktop/screensaver/idle-activation-enabled

If the command does not return a result, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent a user from overriding a screensaver lock after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

     # touch /etc/dconf/db/local.d/locks/session

Add the setting to lock the screensaver idle-activation-enabled setting:

     /org/gnome/desktop/screensaver/idle-activation-enabled'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4527r880783_chk'
  tag severity: 'medium'
  tag gid: 'V-204403'
  tag rid: 'SV-204403r880785_rule'
  tag stig_id: 'RHEL-07-010101'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-4527r880784_fix'
  tag 'documentable'
  tag legacy: ['V-78997', 'SV-93703']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
