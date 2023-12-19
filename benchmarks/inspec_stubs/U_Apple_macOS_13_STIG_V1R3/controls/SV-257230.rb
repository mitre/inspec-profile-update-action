control 'SV-257230' do
  title 'The macOS system must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Verify the macOS system is configured to enforce at least one special character of password complexity with the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "minComplexChars"
 
minComplexChar = 1;

If "minComplexChars" is not set to "1", this is a finding.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowSimple"

allowSimple = 0;

If "allowSimple" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the macOS system to enforce at least one special character of password complexity by installing the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60915r905321_chk'
  tag severity: 'medium'
  tag gid: 'V-257230'
  tag rid: 'SV-257230r905323_rule'
  tag stig_id: 'APPL-13-003011'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-60856r905322_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
