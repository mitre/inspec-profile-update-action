control 'SV-257143' do
  title 'The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'Verify the macOS system is configured to prompt users to enter a password to unlock the screen saver with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -w "askForPassword"

askForPassword = 1;

If there is no result, or if "askForPassword" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to prompt users to enter a password to unlock the screen saver by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60828r905060_chk'
  tag severity: 'medium'
  tag gid: 'V-257143'
  tag rid: 'SV-257143r905062_rule'
  tag stig_id: 'APPL-13-000002'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-60769r905061_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
