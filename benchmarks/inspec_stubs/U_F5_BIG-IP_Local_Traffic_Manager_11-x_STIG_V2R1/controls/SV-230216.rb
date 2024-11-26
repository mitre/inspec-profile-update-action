control 'SV-230216' do
  title 'The BIG-IP Core implementation must be configured to activate a session lock to conceal information previously visible on the display for connections to virtual servers.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The network element session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP LTM is configured to conceal, via a session lock, information previously visible on the display with a publicly viewable image.

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> Protocol >> TCP.

Select a TCP Profile for user sessions.

Verify "Reset On Timeout" is Enabled under the "Settings" section

Verify the BIG-IP LTM is configured to use the Protocol Profile.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select appropriate virtual server.

Verify "Protocol Profile (Client)" is set to a profile that limits session timeout.

If the BIG-IP Core does not conceal, via a session lock, information previously visible on the display with a publicly viewable image, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core to conceal, via a session lock, information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16959r291114_chk'
  tag severity: 'medium'
  tag gid: 'V-230216'
  tag rid: 'SV-230216r561161_rule'
  tag stig_id: 'F5BI-LT-000139'
  tag gtitle: 'SRG-NET-000521-ALG-000002'
  tag fix_id: 'F-16957r291115_fix'
  tag 'documentable'
  tag legacy: ['V-60315', 'SV-74745']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
