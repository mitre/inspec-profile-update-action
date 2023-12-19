control 'SV-209526' do
  title 'The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A default screen saver must be configured for all users, as the screen saver will act as a session time-out lock for the system and must conceal the contents of the screen from unauthorized users. The screen saver must not display any sensitive information or reveal the contents of the locked session screen. Publicly viewable images can include static or dynamic images such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen.'
  desc 'check', 'To view the currently selected screen saver for the logged-on user, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep modulePath

If there is no result or defined "modulePath", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9777r282060_chk'
  tag severity: 'low'
  tag gid: 'V-209526'
  tag rid: 'SV-209526r610285_rule'
  tag stig_id: 'AOSX-14-000006'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-9777r282061_fix'
  tag 'documentable'
  tag legacy: ['SV-104935', 'V-95797']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
