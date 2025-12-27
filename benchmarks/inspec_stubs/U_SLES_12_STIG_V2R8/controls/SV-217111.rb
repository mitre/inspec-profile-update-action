control 'SV-217111' do
  title 'The SUSE operating system must conceal, via the session lock, information previously visible on the display with a publicly viewable image in the graphical user interface.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The SUSE operating system session lock event must include an obfuscation of the display screen to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images conveys sensitive information.'
  desc 'check', %q(Verify the SUSE operating system conceals via the session lock information previously visible on the display with a publicly viewable image in the graphical user interface.

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Check that the lock screen is set to a publicly viewable image by running the following command:

# gsettings get org.gnome.desktop.screensaver picture-uri 
'file:///usr/share/wallpapers/SLE-default-static.xml'

If nothing is returned or "org.gnome.desktop.screensaver" is not set, this is a finding.)
  desc 'fix', %q(Note: If the system does not have X Windows installed, this requirement is Not Applicable.

Configure the SUSE operating system to use a publically viewable image by finding the Settings menu and then navigate to the Background selection section: 

- Click "Applications" on the bottom left.
- Hover over "System Tools" with the mouse.
- Click the "Settings" icon under System Tools.
- Click "Background" and then "Lock Screen".
- Set the Lock Screen image to the user's choice.
- Click "Select".
- Exit Settings Dialog.)
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18339r369489_chk'
  tag severity: 'low'
  tag gid: 'V-217111'
  tag rid: 'SV-217111r603262_rule'
  tag stig_id: 'SLES-12-010100'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-18337r369490_fix'
  tag 'documentable'
  tag legacy: ['SV-91761', 'V-77065']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
