control 'SV-234814' do
  title 'The SUSE operating system must conceal, via the session lock, information previously visible on the display with a publicly viewable image in the graphical user interface (GUI).'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The SUSE operating system session lock event must include an obfuscation of the display screen to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images conveys sensitive information.'
  desc 'check', %q(Verify the SUSE operating system conceals via the session lock information previously visible on the display with a publicly viewable image in the GUI.

Note: If the system does not have X Windows installed, this requirement is Not Applicable.

Check that the lock screen is set to a publicly viewable image by running the following command:

> sudo gsettings get org.gnome.desktop.screensaver picture-uri 
'file:///usr/share/wallpapers/SLE-default-static.xml'

If nothing is returned or "org.gnome.desktop.screensaver" is not set, this is a finding.)
  desc 'fix', %q(Note: If the system does not have X Windows installed, this requirement is Not Applicable.

Configure the SUSE operating system to use a publically viewable image by finding the Settings menu and then navigate to the Background selection section: 

- Click "Activities" on the top left.
- Click "Show Applications" at the bottom of the Activities menu.
- Click the "Settings" icon.
- Click "Background" from left hand menu.
- Select image and set the Lock Screen image to the user's choice.
- Exit Settings Dialog.)
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38002r618711_chk'
  tag severity: 'low'
  tag gid: 'V-234814'
  tag rid: 'SV-234814r622137_rule'
  tag stig_id: 'SLES-15-010140'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-37965r618712_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
