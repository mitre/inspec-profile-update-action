control 'SV-257147' do
  title 'The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A default screen saver must be configured for all users, as the screen saver will act as a session timeout lock for the system and must conceal the contents of the screen from unauthorized users. The screen saver must not display any sensitive information or reveal the contents of the locked session screen. Publicly viewable images can include static or dynamic images such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen.'
  desc 'check', 'Verify the macOS system is configured with a screen saver with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "moduleName"

moduleName = Ventura;

If there is no result or the "moduleName" is undefined, this is a finding.'
  desc 'fix', 'Configure the macOS system with a screen saver by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60832r905072_chk'
  tag severity: 'medium'
  tag gid: 'V-257147'
  tag rid: 'SV-257147r905074_rule'
  tag stig_id: 'APPL-13-000006'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-60773r905073_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
