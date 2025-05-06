control 'SV-234276' do
  title 'The UEM server must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically at the operating system level, but may be at the application level. 

When the application design specifies the application rather than the operating system will determine when to lock the session, the application session lock event must include an obfuscation of the display screen to prevent other users from reading what was previously displayed. 

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431011'
  desc 'check', 'Verify the UEM server conceals, via the session lock, information previously visible on the display with a publicly viewable image.

If the UEM server does not conceal via the session lock information previously visible on the display with a publicly viewable image, this is a finding.'
  desc 'fix', 'Configure the UEM server to conceal via the session lock information previously visible on the display with a publicly viewable image.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37461r613838_chk'
  tag severity: 'medium'
  tag gid: 'V-234276'
  tag rid: 'SV-234276r879512_rule'
  tag stig_id: 'SRG-APP-000002-UEM-000002'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-37426r613839_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
