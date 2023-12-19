control 'SV-91659' do
  title 'If multifactor authentication is not supported and passwords must be used, the DBN-6300 must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'To see if the system requires password complexity attempt to change your password to a non-conforming password.

If the user is able to change their password without meeting the requirement, this is a finding.'
  desc 'fix', 'Set the password-complexity variable within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:
reg set /sysconfig/auth/01 {"stores": {"local": {"policies": {"passwordQuality": {"owasp": {"enable": true,"allowPassphrases": false }}}}}}'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76589r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76963'
  tag rid: 'SV-91659r1_rule'
  tag stig_id: 'DBNW-DM-000057'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-83659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
