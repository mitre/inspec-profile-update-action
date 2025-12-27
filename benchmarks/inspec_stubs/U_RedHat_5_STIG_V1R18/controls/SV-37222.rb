control 'SV-37222' do
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc 'To protect the on-screen content of a session, it must be replaced with a publicly-viewable pattern upon session lock. Examples of publicly viewable patterns include screen saver patterns, photographic images, solid colors, or a blank screen, so long as none of those patterns convey sensitive information.

This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems using remote access protocols.'
  desc 'check', 'Determine if a publicly-viewable pattern is displayed during a session lock. Some screensaver themes available but not included in the RHEL distribution use a snapshot of the current screen as a graphic. This theme does not qualify as a publicly-viewable pattern. If the session lock pattern is not publicly-viewable this is a finding.'
  desc 'fix', 'Configure the system to display a publicly-viewable pattern during a session lock. This is done graphically by selecting a screensaver theme using gnome-screensaver-preferences command. Any of the themes distributed with RHEL may be used including "Blank Screen".'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35911r1_chk'
  tag severity: 'low'
  tag gid: 'V-22301'
  tag rid: 'SV-37222r1_rule'
  tag stig_id: 'GEN000510'
  tag gtitle: 'GEN000510'
  tag fix_id: 'F-31169r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000061']
  tag nist: ['AC-14 a']
end
