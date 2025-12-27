control 'SV-90767' do
  title 'The OS X system must enforce a minimum 15-character password length.'
  desc 'The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength

The parameter minLength should be "15". 

If it is less than "15", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.

Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user creation operations, as well as lock out all local users, including administrators.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76079'
  tag rid: 'SV-90767r1_rule'
  tag stig_id: 'AOSX-12-000590'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-82717r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
