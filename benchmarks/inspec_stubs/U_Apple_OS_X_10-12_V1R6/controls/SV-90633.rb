control 'SV-90633' do
  title 'The OS X system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A default screen saver must be configured for all users, as the screen saver will act as a session time-out lock for the system and must conceal the contents of the screen from unauthorized users. The screen saver must not display any sensitive information or reveal the contents of the locked session screen. Publicly viewable images can include static or dynamic images such as patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen.'
  desc 'check', 'To view the currently selected screen saver for the logged-on user, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep loginWindowModulePath

If there is no result or defined "loginWindowModulePath", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75627r1_chk'
  tag severity: 'low'
  tag gid: 'V-75945'
  tag rid: 'SV-90633r1_rule'
  tag stig_id: 'AOSX-12-000005'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-82583r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
