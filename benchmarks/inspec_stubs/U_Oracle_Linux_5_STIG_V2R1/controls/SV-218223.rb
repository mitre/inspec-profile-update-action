control 'SV-218223' do
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc 'To protect the on-screen content of a session, it must be replaced with a publicly-viewable pattern upon session lock. Examples of publicly viewable patterns include screen saver patterns, photographic images, solid colors, or a blank screen, so long as none of those patterns convey sensitive information.

This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems using remote access protocols.'
  desc 'check', 'Determine if a publicly-viewable pattern is displayed during a session lock.  Some screensaver themes available but not included in the operating system distribution use a snapshot of the current screen as a graphic.  This theme does not qualify as a publicly-viewable pattern.  

If the screen lock pattern is not publicly-viewable, this is a finding.'
  desc 'fix', 'Configure the system to display a publicly-viewable pattern during a session lock. This is done graphically by selecting a screensaver theme using gnome-screensaver-preferences command.  Any of the themes distributed with this operating system may be used including "Blank Screen".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19698r568573_chk'
  tag severity: 'low'
  tag gid: 'V-218223'
  tag rid: 'SV-218223r603259_rule'
  tag stig_id: 'GEN000510'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19696r568574_fix'
  tag 'documentable'
  tag legacy: ['V-22301', 'SV-63633']
  tag cci: ['CCI-000061', 'CCI-000366']
  tag nist: ['AC-14 a', 'CM-6 b']
end
