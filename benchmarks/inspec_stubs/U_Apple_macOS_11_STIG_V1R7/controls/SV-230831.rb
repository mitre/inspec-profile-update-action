control 'SV-230831' do
  title 'The macOS system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep requireAlphanumeric

If the return is not “requireAlphanumeric = 1”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33776r607380_chk'
  tag severity: 'medium'
  tag gid: 'V-230831'
  tag rid: 'SV-230831r599842_rule'
  tag stig_id: 'APPL-11-003007'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-33749r607381_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
