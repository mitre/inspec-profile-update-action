control 'SV-214895' do
  title 'The macOS system logon window must be configured to prompt for username and password, rather than show a list of users.'
  desc 'The logon window must be configured to prompt all users for both a username and a password. By default, the system displays a list of known users at the logon screen. This gives an advantage to an attacker with physical access to the system, as the attacker would only have to guess the password for one of the listed accounts.'
  desc 'check', 'To check if the logon window is configured to prompt for user name and password, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SHOWFULLNAME

If there is no result, or "SHOWFULLNAME" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16095r397257_chk'
  tag severity: 'medium'
  tag gid: 'V-214895'
  tag rid: 'SV-214895r609363_rule'
  tag stig_id: 'AOSX-13-000930'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16093r397258_fix'
  tag 'documentable'
  tag legacy: ['V-81669', 'SV-96383']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
