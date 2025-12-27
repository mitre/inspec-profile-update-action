control 'SV-214807' do
  title 'The macOS system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay

If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Security and Privacy Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16007r396993_chk'
  tag severity: 'medium'
  tag gid: 'V-214807'
  tag rid: 'SV-214807r609363_rule'
  tag stig_id: 'AOSX-13-000025'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-16005r396994_fix'
  tag 'documentable'
  tag legacy: ['SV-96187', 'V-81473']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
