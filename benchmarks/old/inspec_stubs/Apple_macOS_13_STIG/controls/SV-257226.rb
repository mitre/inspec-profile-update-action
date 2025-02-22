control 'SV-257226' do
  title 'The macOS system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the macOS system is configured to require at least one numeric character in password complexity with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "requireAlphanumeric"

requireAlphanumeric = 1;

If the result is not "requireAlphanumeric = 1", this is a finding.'
  desc 'fix', 'Configure the macOS system to require at least one numeric character in password complexity by installing the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60911r905309_chk'
  tag severity: 'medium'
  tag gid: 'V-257226'
  tag rid: 'SV-257226r905311_rule'
  tag stig_id: 'APPL-13-003007'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-60852r905310_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
