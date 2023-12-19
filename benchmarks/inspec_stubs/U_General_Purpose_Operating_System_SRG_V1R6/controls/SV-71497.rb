control 'SV-71497' do
  title 'The operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the operating system automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57237'
  tag rid: 'SV-71497r1_rule'
  tag stig_id: 'SRG-OS-000329-GPOS-00128'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-62169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
