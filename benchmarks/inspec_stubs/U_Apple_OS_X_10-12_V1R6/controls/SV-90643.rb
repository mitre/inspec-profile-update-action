control 'SV-90643' do
  title 'The OS X system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay

If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75955'
  tag rid: 'SV-90643r1_rule'
  tag stig_id: 'AOSX-12-000025'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-82593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
