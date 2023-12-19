control 'SV-38939' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'fix', 'Use the chsec command to set the maxage field to 8 for each user.

# chsec -f /etc/security/user -s default -a maxage=8
# chuser maxage=8 < user id >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-11976'
  tag rid: 'SV-38939r1_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'GEN000700'
  tag fix_id: 'F-32059r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000180']
  tag nist: ['IA-5 f']
end
