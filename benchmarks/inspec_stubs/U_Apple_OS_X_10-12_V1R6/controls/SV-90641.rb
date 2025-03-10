control 'SV-90641' do
  title 'The OS X system must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc "Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account."
  desc 'check', 'To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPassword

If there is no result, or if "askForPassword" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75637r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75953'
  tag rid: 'SV-90641r1_rule'
  tag stig_id: 'AOSX-12-000020'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-82591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
