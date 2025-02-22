control 'SV-216363' do
  title 'The operating system must provide the capability for users to directly initiate session lock mechanisms.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the system but does not want to log out because of the temporary nature of the absence. 

Rather than be forced to wait for a period of time to expire before the user session can be locked, the operating system needs to provide users with the ability to manually invoke a session lock so users may secure their account should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Determine whether the lock screen function works correctly.

For Solaris 11, 11.1, 11.2, and 11.3:
In the GNOME 2 desktop System >> Lock Screen.

For Solaris 11.4 or newer:
In the GNOME 3 desktop Status Menu (top right corner) >> Lock Icon, check that the screen locks and displays the "password" prompt.

Check that "Disable Screensaver" is not selected in the GNOME Screensaver preferences. 

If the screen does not lock or the "Disable Screensaver" option is selected, this is a finding.'
  desc 'fix', 'User-initiated session lock is accessible from the GNOME graphical desktop menu GNOME 2: System >> Lock Screen.

GNOME 3: Status Menu (top right corner) >> Lock Icon.

However, the user has the option to disable screensaver lock.

For Solaris 11, 11.1, 11.2, and 11.3:
In the GNOME 2 desktop: System >> Preferences >> Screensaver.

For Solaris 11.4 or newer:
If using the default GNOME desktop: Activities >> Show Applications >> select "Screensaver" Icon.

If using the GNOME Classic desktop: Applications >> Other >> Screensaver.

Ensure that "Mode" is set to "Blank Screen only".'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17599r371177_chk'
  tag severity: 'medium'
  tag gid: 'V-216363'
  tag rid: 'SV-216363r603267_rule'
  tag stig_id: 'SOL-11.1-040460'
  tag gtitle: 'SRG-OS-000030'
  tag fix_id: 'F-17597r371178_fix'
  tag 'documentable'
  tag legacy: ['V-48135', 'SV-61007']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
