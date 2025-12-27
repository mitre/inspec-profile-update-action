control 'SV-203594' do
  title 'The operating system must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify that the operating system enforces the limit of three consecutive invalid logon attempts by a user during a 15-minute time period. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3719r557038_chk'
  tag severity: 'medium'
  tag gid: 'V-203594'
  tag rid: 'SV-203594r557040_rule'
  tag stig_id: 'SRG-OS-000021-GPOS-00005'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-3719r557039_fix'
  tag 'documentable'
  tag legacy: ['V-56579', 'SV-70839']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
