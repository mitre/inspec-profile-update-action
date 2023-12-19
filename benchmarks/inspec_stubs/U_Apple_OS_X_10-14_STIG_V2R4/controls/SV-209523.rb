control 'SV-209523' do
  title 'The macOS system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay

If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9774r282051_chk'
  tag severity: 'medium'
  tag gid: 'V-209523'
  tag rid: 'SV-209523r610285_rule'
  tag stig_id: 'AOSX-14-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-9774r282052_fix'
  tag 'documentable'
  tag legacy: ['SV-104929', 'V-95791']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
