control 'SV-214880' do
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
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16080r397212_chk'
  tag severity: 'medium'
  tag gid: 'V-214880'
  tag rid: 'SV-214880r609363_rule'
  tag stig_id: 'AOSX-13-000587'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-16078r397213_fix'
  tag 'documentable'
  tag legacy: ['SV-96353', 'V-81639']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
