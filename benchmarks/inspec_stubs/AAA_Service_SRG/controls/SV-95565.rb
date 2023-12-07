control 'SV-95565' do
  title 'AAA Services must be configured to maintain locks on user accounts until released by an administrator.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are configured to maintain locks on user accounts until released by an administrator.

If AAA Services are not configured to maintain locks on user accounts until released by an administrator, this is a finding.'
  desc 'fix', 'Configure AAA Services to maintain locks on user accounts until released by an administrator.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80591r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80855'
  tag rid: 'SV-95565r1_rule'
  tag stig_id: 'SRG-APP-000345-AAA-000210'
  tag gtitle: 'SRG-APP-000345-AAA-000210'
  tag fix_id: 'F-87709r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
