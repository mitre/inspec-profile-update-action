control 'SV-203601' do
  title 'The operating system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The operating system session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'Verify the operating system conceals, via the session lock, information previously visible on the display with a publicly viewable image. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3726r557059_chk'
  tag severity: 'medium'
  tag gid: 'V-203601'
  tag rid: 'SV-203601r557061_rule'
  tag stig_id: 'SRG-OS-000031-GPOS-00012'
  tag gtitle: 'SRG-OS-000031'
  tag fix_id: 'F-3726r557060_fix'
  tag 'documentable'
  tag legacy: ['SV-70897', 'V-56637']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
