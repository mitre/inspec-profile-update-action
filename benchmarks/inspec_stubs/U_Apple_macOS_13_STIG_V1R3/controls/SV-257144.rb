control 'SV-257144' do
  title 'The macOS system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'Verify the macOS system is configured to initiate a session lock within five seconds of the screen saver starting with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "askForPasswordDelay"

askForPasswordDelay = 5;

If there is no result, or if "askForPasswordDelay" is not set to "5" or less, this is a finding.'
  desc 'fix', 'Configure the macOS system to initiate a session lock within five seconds of the screen saver starting by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60829r905063_chk'
  tag severity: 'medium'
  tag gid: 'V-257144'
  tag rid: 'SV-257144r905065_rule'
  tag stig_id: 'APPL-13-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-60770r905064_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
