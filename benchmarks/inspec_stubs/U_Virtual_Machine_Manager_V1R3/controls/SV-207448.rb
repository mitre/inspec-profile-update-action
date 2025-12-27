control 'SV-207448' do
  title 'The VMM must automatically lock an account until the locked account is released by an administrator, when three unsuccessful logon attempts in 15 minutes are made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the VMM automatically locks an account until the locked account is released by an administrator, when three unsuccessful logon attempts in 15 minutes are made.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically lock an account until the locked account is released by an administrator, when three unsuccessful logon attempts in 15 minutes are made.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7705r365754_chk'
  tag severity: 'medium'
  tag gid: 'V-207448'
  tag rid: 'SV-207448r854621_rule'
  tag stig_id: 'SRG-OS-000329-VMM-001180'
  tag gtitle: 'SRG-OS-000329'
  tag fix_id: 'F-7705r365755_fix'
  tag 'documentable'
  tag legacy: ['SV-71357', 'V-57097']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
