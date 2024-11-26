control 'SV-223575' do
  title 'IBM z/OS must employ a session manager that conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The operating system session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to conceal, via the session lock, information previously visible on the display with a publicly viewable image, this is a finding.'
  desc 'fix', 'Configure the session manager to conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25248r500860_chk'
  tag severity: 'medium'
  tag gid: 'V-223575'
  tag rid: 'SV-223575r533198_rule'
  tag stig_id: 'ACF2-OS-002350'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-25236r500861_fix'
  tag 'documentable'
  tag legacy: ['V-97855', 'SV-106959']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
