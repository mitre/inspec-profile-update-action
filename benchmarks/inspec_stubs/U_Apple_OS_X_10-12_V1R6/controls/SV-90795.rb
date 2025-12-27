control 'SV-90795' do
  title 'The OS X system logon window must be configured to prompt for username and password, rather than show a list of users.'
  desc 'The logon window must be configured to prompt all users for both a username and a password. By default, the system displays a list of known users at the logon screen. This gives an advantage to an attacker with physical access to the system, as the attacker would only have to guess the password for one of the listed accounts.'
  desc 'check', 'To check if the logon window is configured to prompt for user name and password, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SHOWFULLNAME

If there is no result, or "SHOWFULLNAME" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76107'
  tag rid: 'SV-90795r1_rule'
  tag stig_id: 'AOSX-12-000930'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-82745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
