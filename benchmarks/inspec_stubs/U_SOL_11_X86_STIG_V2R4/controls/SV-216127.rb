control 'SV-216127' do
  title 'The operating system session lock mechanism, when activated on a device with a display screen, must place a publicly viewable pattern onto the associated display, hiding what was previously visible on the screen.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the system but does not log out because of the temporary nature of the absence. 

The session lock will also include an obfuscation of the display screen to prevent other users from reading what was previously displayed.'
  desc 'check', 'For Solaris 11, 11.1, 11.2, and 11.3:
In the GNOME 2 desktop System >> Preferences >> Screensaver.

For Solaris 11.4 or newer:
If using the default GNOME desktop: Activities >> Show Applications >> select "Screensaver" icon.

If using the GNOME Classic desktop: Applications >> Other >> Screensaver menu item the user can select other screens or disable screensaver.

Check that "Disable Screensaver" is not selected in the Gnome Screensaver preferences. 

If "Disable Screensaver" is selected or "Blank Screen Only" is not selected, this is a finding.'
  desc 'fix', %q(For Solaris 11, 11.1, 11.2, and 11.3:
In the GNOME 2 desktop: System >> Preferences >> Screensaver.

For Solaris 11.4 or newer:
If using the default GNOME desktop: Activities >> Show Applications >> select “Screensaver” icon.

If using the GNOME Classic desktop: Applications >> Other >> Screensaver.

Click on Mode's pull-down.

Select: "Blank Screen Only". 

Ensure that "Blank Screen Only" is selected.)
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17365r372763_chk'
  tag severity: 'medium'
  tag gid: 'V-216127'
  tag rid: 'SV-216127r603268_rule'
  tag stig_id: 'SOL-11.1-040470'
  tag gtitle: 'SRG-OS-000031'
  tag fix_id: 'F-17363r372764_fix'
  tag 'documentable'
  tag legacy: ['V-48139', 'SV-61011']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
