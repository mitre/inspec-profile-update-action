control 'SV-248682' do
  title 'OL 8 must prevent a user from overriding the session lock-delay setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock. 
 
The session lock is implemented at the point where session activity can be determined and/or controlled. 
 
Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide. 
 
Locking these settings from non-privileged users is crucial to maintaining a protected baseline.

"
  desc 'check', 'Note: This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Verify the operating system prevents a user from overriding settings for graphical user interfaces. 
 
Determine which profile the system database is using with the following command: 
 
$ sudo grep system-db /etc/dconf/profile/user 
 
system-db:local 
 
Check that graphical settings are locked from non-privileged user modification with the following command. 
 
Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used. 
 
$ sudo grep -i lock-delay /etc/dconf/db/local.d/locks/* 
 
/org/gnome/desktop/screensaver/lock-delay 
 
If the command does not return at least the example result, this is a finding.'
  desc 'fix', 'Configure OL 8 to prevent a user from overriding settings for graphical user interfaces. 
 
Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command. 
 
Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory. 
 
$ sudo touch /etc/dconf/db/local.d/locks/session 
 
Add the following setting to prevent non-privileged users from modifying it: 

/org/gnome/desktop/screensaver/lock-delay'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52116r779610_chk'
  tag severity: 'medium'
  tag gid: 'V-248682'
  tag rid: 'SV-248682r779612_rule'
  tag stig_id: 'OL08-00-020080'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-52070r779611_fix'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
end
