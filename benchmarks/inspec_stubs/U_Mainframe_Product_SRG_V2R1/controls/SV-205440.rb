control 'SV-205440' do
  title 'The Mainframe Product must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically at the operating system-level, but may be at the application-level. 

When the application design specifies the application rather than the operating system will determine when to lock the session, the application session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed. 

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'If the Mainframe Product has no data screen capability, this requirement is not applicable.

Examine configuration parameters to determine whether information previously displayed on the screen is concealed at a session lock. 

If information is not concealed, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to conceal previously displayed information at a session lock.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5706r299553_chk'
  tag severity: 'medium'
  tag gid: 'V-205440'
  tag rid: 'SV-205440r395445_rule'
  tag stig_id: 'SRG-APP-000002-MFP-000002'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-5706r299554_fix'
  tag 'documentable'
  tag legacy: ['SV-82599', 'V-68109']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
