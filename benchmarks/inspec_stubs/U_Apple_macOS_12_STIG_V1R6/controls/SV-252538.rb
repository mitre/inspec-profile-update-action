control 'SV-252538' do
  title 'The macOS system logon window must be configured to prompt for username and password, rather than show a list of users.'
  desc 'The logon window must be configured to prompt all users for both a username and a password. By default, the system displays a list of known users at the logon screen. This gives an advantage to an attacker with physical access to the system, as the attacker would only have to guess the password for one of the listed accounts.'
  desc 'check', 'To check if the logon window is configured to prompt for user name and password, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SHOWFULLNAME

If there is no result, or "SHOWFULLNAME" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55994r816426_chk'
  tag severity: 'low'
  tag gid: 'V-252538'
  tag rid: 'SV-252538r877377_rule'
  tag stig_id: 'APPL-12-005052'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-55944r816427_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
