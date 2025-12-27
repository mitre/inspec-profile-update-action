control 'SV-38936' do
  title 'The system must require passwords to contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'fix', 'Change the minimum password length to 15 or more. 

# chsec -f /etc/security/user -s default -a minlen=15
# chuser minlen=15 <user id>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-38936r2_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-31635r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
