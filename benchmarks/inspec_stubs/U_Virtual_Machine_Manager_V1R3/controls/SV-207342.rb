control 'SV-207342' do
  title 'The VMM must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized VMM access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account. This restriction may be relaxed for administrative accounts to avoid potential Denial of Service.'
  desc 'check', 'Verify the VMM enforces the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, by locking the account.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7599r365436_chk'
  tag severity: 'medium'
  tag gid: 'V-207342'
  tag rid: 'SV-207342r378517_rule'
  tag stig_id: 'SRG-OS-000021-VMM-000050'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-7599r365437_fix'
  tag 'documentable'
  tag legacy: ['SV-71093', 'V-56833']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
