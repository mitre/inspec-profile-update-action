control 'SV-207349' do
  title 'The VMM must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the VMM but does not log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. The VMM session lock event must include an obfuscation of the display screen to prevent other users from reading what was previously displayed. 

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'Verify the VMM conceals, via the session lock, information previously visible on the display with a publicly viewable image. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7606r365457_chk'
  tag severity: 'medium'
  tag gid: 'V-207349'
  tag rid: 'SV-207349r378604_rule'
  tag stig_id: 'SRG-OS-000031-VMM-000120'
  tag gtitle: 'SRG-OS-000031'
  tag fix_id: 'F-7606r365458_fix'
  tag 'documentable'
  tag legacy: ['V-56867', 'SV-71127']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
