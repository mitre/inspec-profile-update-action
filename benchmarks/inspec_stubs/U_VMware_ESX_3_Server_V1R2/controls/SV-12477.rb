control 'SV-12477' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'check', 'Verify the system requires passwords be changed at least every 60 days.'
  desc 'fix', 'Configure the system to require passwords be changed at least every 60 days.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7941r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11976'
  tag rid: 'SV-12477r2_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'GEN000700'
  tag fix_id: 'F-24396r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000180']
  tag nist: ['IA-5 f']
end
