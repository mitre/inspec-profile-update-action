control 'SV-95561' do
  title 'AAA Services must be configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.

If AAA Services are not configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80851'
  tag rid: 'SV-95561r1_rule'
  tag stig_id: 'SRG-APP-000065-AAA-000200'
  tag gtitle: 'SRG-APP-000065-AAA-000200'
  tag fix_id: 'F-87705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
