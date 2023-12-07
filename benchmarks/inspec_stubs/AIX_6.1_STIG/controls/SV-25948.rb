control 'SV-25948' do
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc 'To protect the on-screen content of a session, it must be replaced with a publicly-viewable pattern upon session lock. Examples of publicly viewable patterns include screen saver patterns, photographic images, solid colors, or a blank screen, so long as none of those patterns convey sensitive information.

This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems using remote access protocols.'
  desc 'check', 'Determine if a publicly-viewable pattern is displayed during a session lock. If the session lock pattern is not publicly-viewable, this is a finding.'
  desc 'fix', 'Configure the system to display a publicly-viewable pattern during a session lock.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-29092r1_chk'
  tag severity: 'low'
  tag gid: 'V-22301'
  tag rid: 'SV-25948r1_rule'
  tag stig_id: 'GEN000510'
  tag gtitle: 'GEN000510'
  tag fix_id: 'F-26091r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000061']
  tag nist: ['AC-14 a']
end
