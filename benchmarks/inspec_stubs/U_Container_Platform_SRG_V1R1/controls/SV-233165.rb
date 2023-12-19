control 'SV-233165' do
  title 'The container platform must automatically lock an account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Determine if the container platform is configured to automatically lock an account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded. 

If the container platform is not configured to lock the account, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically lock an account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36101r599620_chk'
  tag severity: 'medium'
  tag gid: 'V-233165'
  tag rid: 'SV-233165r599621_rule'
  tag stig_id: 'SRG-APP-000345-CTR-000785'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-36069r599132_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
