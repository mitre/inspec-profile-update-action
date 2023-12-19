control 'SV-230744' do
  title 'The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPassword

If there is no result, or if "askForPassword" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33689r607118_chk'
  tag severity: 'medium'
  tag gid: 'V-230744'
  tag rid: 'SV-230744r599842_rule'
  tag stig_id: 'APPL-11-000002'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-33662r607119_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
