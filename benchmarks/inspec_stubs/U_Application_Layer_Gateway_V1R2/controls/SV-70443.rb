control 'SV-70443' do
  title 'The ALG providing user access control intermediary services must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The network element session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG conceals, via the session lock, information previously visible on the display with a publicly viewable image.

If the ALG does not conceal, via the session lock, information previously visible on the display with a publicly viewable image, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56739r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56189'
  tag rid: 'SV-70443r1_rule'
  tag stig_id: 'SRG-NET-000521-ALG-000002'
  tag gtitle: 'SRG-NET-000521-ALG-000002'
  tag fix_id: 'F-61065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
