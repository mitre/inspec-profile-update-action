control 'SV-203698' do
  title 'The operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the operating system automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3823r375041_chk'
  tag severity: 'medium'
  tag gid: 'V-203698'
  tag rid: 'SV-203698r379606_rule'
  tag stig_id: 'SRG-OS-000329-GPOS-00128'
  tag gtitle: 'SRG-OS-000329'
  tag fix_id: 'F-3823r375042_fix'
  tag 'documentable'
  tag legacy: ['V-57237', 'SV-71497']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
