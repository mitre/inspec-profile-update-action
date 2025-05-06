control 'SV-233031' do
  title 'The container platform must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Review the container platform to determine if it is configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

If the container platform is not configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35967r599514_chk'
  tag severity: 'medium'
  tag gid: 'V-233031'
  tag rid: 'SV-233031r599515_rule'
  tag stig_id: 'SRG-APP-000065-CTR-000115'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-35935r598730_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
