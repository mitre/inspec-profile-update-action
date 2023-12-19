control 'SV-257244' do
  title 'The macOS system logon window must be configured to prompt for username and password.'
  desc 'The logon window must be configured to prompt all users for both a username and a password. By default, the system displays a list of known users at the logon screen. This gives an advantage to an attacker with physical access to the system, as the attacker would only have to guess the password for one of the listed accounts.'
  desc 'check', 'Verify the macOS system is configured to prompt for username and password at the logon window with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "SHOWFULLNAME"

SHOWFULLNAME = 1;

If "SHOWFULLNAME" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to prompt for username and password at the logon window by installing the "Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60929r905363_chk'
  tag severity: 'medium'
  tag gid: 'V-257244'
  tag rid: 'SV-257244r905365_rule'
  tag stig_id: 'APPL-13-005052'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-60870r905364_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
