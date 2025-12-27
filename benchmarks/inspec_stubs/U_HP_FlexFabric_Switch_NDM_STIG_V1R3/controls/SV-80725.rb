control 'SV-80725' do
  title 'The HP FlexFabric Switch must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Determine if the HP FlexFabric Switch automatically locks the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

[HP] display local-user

Device management user admin:
  State:                     Active
  Service type:              SSH/Terminal
  User group:                system
  Bind attributes:
  Authorization attributes:
    Work directory:          cfa0:
    User role list:          network-admin, network-operator
  Password control configurations:
    Maximum login attempts:  3
    Action for exceeding login attempts: Lock user for 15 minutes

If an account is not automatically locked out until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

[HP] local-user test
[HP-luser-test] password-control login-attempt 3 exceed lock-time 15'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66235'
  tag rid: 'SV-80725r1_rule'
  tag stig_id: 'HFFS-ND-000092'
  tag gtitle: 'SRG-APP-000345-NDM-000290'
  tag fix_id: 'F-72311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
