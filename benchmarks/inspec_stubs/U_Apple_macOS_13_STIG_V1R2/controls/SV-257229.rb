control 'SV-257229' do
  title 'The macOS system must enforce a minimum 15-character password length.'
  desc 'The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the macOS system is configured to enforce a minimum 15-character password length with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "minLength"

minLength = 15;

If "minLength" is not set to "15", this is a finding.'
  desc 'fix', 'Configure the macOS system to enforce a 15-character password length by installing the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60914r905318_chk'
  tag severity: 'medium'
  tag gid: 'V-257229'
  tag rid: 'SV-257229r905320_rule'
  tag stig_id: 'APPL-13-003010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-60855r905319_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
