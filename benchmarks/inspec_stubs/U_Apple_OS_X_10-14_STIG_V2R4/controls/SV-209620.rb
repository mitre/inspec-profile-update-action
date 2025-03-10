control 'SV-209620' do
  title 'The macOS system must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following command to check if the system is configured to require that passwords contain at least one special character:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minComplexChars

If the return is null or not ” minComplexChars = 1”, this is a finding.

Run the following command to check if the system is configured to require that passwords not contain repeated sequential characters or characters in increasing and decreasing sequential order:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowSimple

If "allowSimple" is not set to "0" or is undefined, this is a finding.'
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9871r282342_chk'
  tag severity: 'medium'
  tag gid: 'V-209620'
  tag rid: 'SV-209620r610285_rule'
  tag stig_id: 'AOSX-14-003011'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-9871r282343_fix'
  tag 'documentable'
  tag legacy: ['SV-105109', 'V-95971']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
