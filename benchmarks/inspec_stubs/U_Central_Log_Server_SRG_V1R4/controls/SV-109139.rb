control 'SV-109139' do
  title 'The Central Log Server must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to lock out the account until released by an administrator when 3 consecutive invalid attempts during a 15 minute period is exceeded.

If the Central Log Server is not configured to lock out the account until released by an administrator when 3 consecutive invalid attempts in 15 minutes is exceeded, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to lock out the account until released by an administrator when 3 consecutive invalid attempts during a 15 minute period is exceeded.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100035'
  tag rid: 'SV-109139r1_rule'
  tag stig_id: 'SRG-APP-000345-AU-000400'
  tag gtitle: 'SRG-APP-000345-AU-000400'
  tag fix_id: 'F-105719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
