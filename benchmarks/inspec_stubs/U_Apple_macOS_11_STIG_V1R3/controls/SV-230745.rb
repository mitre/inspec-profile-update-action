control 'SV-230745' do
  title 'The macOS system must initiate the session lock no more than five seconds after a screen saver is started.'
  desc 'A screen saver must be enabled and set to require a password to unlock.  An excessive grace period impacts the ability for a session to be truly locked, requiring authentication to unlock.'
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay

If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33690r607121_chk'
  tag severity: 'medium'
  tag gid: 'V-230745'
  tag rid: 'SV-230745r599842_rule'
  tag stig_id: 'APPL-11-000003'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-33663r607122_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
