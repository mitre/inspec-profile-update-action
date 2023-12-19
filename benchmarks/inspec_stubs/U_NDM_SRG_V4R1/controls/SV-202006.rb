control 'SV-202006' do
  title 'The network device must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device.  The network management session lock event must include an obfuscation of the display screen to prevent other users from reading what was previously displayed. 

Permitted publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'Review the network device configuration to see if the device conceals information previously visible on the display with a publicly viewable image during the session lock.  This can be demonstrated by the network administrator. If previously visible information is not concealed with a publicly viewable image by the session lock, this is a finding.'
  desc 'fix', 'Configure the network device to conceal information previously visible on the display with a publicly viewable image during the session lock.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2132r381557_chk'
  tag severity: 'medium'
  tag gid: 'V-202006'
  tag rid: 'SV-202006r395445_rule'
  tag stig_id: 'SRG-APP-000002-NDM-000201'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-2133r381558_fix'
  tag 'documentable'
  tag legacy: ['SV-69275', 'V-55029']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
