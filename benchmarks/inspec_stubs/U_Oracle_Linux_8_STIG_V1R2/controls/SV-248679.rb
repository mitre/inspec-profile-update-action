control 'SV-248679' do
  title 'OL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. 
 
Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system. 
 
OL 8 includes "authselect" as a tool to configure system identity, authentication sources, and providers by selecting a specific profile. A profile is a set of files that describes the resulting system configuration. When a profile is selected, "authselect" will create the "nsswitch.conf" and "PAM" stack to use identity and authentication sources defined by the profile.

'
  desc 'check', %q(Verify the operating system enables a user's session lock until that user reestablishes access using established identification and authentication procedures with the following command:
 
This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo grep -r removal-action /etc/dconf/db/*

/etc/dconf/db/distro.d/20-authselect:removal-action='lock-screen'

If the "removal-action='lock-screen'" setting is missing or commented out from the "dconf" database files, this is a finding.)
  desc 'fix', %q(Configure OL 8 to enable a user's session lock until that user reestablishes access using established identification and authentication procedures. 
 
Select/create an "authselect" profile and incorporate the "with-smartcard-lock-on-removal" feature as in the following example: 
 
$ sudo authselect select sssd with-smartcard with-smartcard-lock-on-removal 
 
Alternatively, the "dconf" settings can be edited in the "/etc/dconf/db/*" location. 
 
Edit or add the "[org/gnome/settings-daemon/peripherals/smartcard]" section of the database file and add or update the following line: 
 
removal-action='lock-screen' 
 
Update the system databases: 
 
$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52113r818654_chk'
  tag severity: 'medium'
  tag gid: 'V-248679'
  tag rid: 'SV-248679r818655_rule'
  tag stig_id: 'OL08-00-020050'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-52067r779602_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
