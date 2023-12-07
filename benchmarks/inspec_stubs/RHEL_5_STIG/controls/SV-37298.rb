control 'SV-37298' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'fix', 'Set the max days field to 60 for all user accounts.
# passwd -x 60 <user>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11976'
  tag rid: 'SV-37298r1_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'GEN000700'
  tag fix_id: 'F-31246r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000180']
  tag nist: ['IA-5 f']
end
