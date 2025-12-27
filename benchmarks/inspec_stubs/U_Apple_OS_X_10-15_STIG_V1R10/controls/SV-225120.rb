control 'SV-225120' do
  title 'The macOS system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay

If there is no result, or if "askForPasswordDelay" is not set to "5" or less, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26819r877372_chk'
  tag severity: 'medium'
  tag gid: 'V-225120'
  tag rid: 'SV-225120r877373_rule'
  tag stig_id: 'AOSX-15-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-26807r467529_fix'
  tag 'documentable'
  tag legacy: ['V-102655', 'SV-111617']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
