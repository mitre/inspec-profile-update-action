control 'SV-70839' do
  title 'The operating system must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify that the operating system enforces the limit of three consecutive invalid logon attempts by a user during a 15-minute time period. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57149r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56579'
  tag rid: 'SV-70839r1_rule'
  tag stig_id: 'SRG-OS-000021-GPOS-00005'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-61475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
