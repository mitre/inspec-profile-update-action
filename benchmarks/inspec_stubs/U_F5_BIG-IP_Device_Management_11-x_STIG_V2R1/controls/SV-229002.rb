control 'SV-229002' do
  title 'The BIG-IP appliance must be configured to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured remote authentication server to automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that automatically locks the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

If an account is not automatically locked out until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured remote authentication server to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31317r518051_chk'
  tag severity: 'medium'
  tag gid: 'V-229002'
  tag rid: 'SV-229002r557520_rule'
  tag stig_id: 'F5BI-DM-000185'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31294r518052_fix'
  tag 'documentable'
  tag legacy: ['V-60195', 'SV-74625']
  tag cci: ['CCI-000366', 'CCI-002238']
  tag nist: ['CM-6 b', 'AC-7 b']
end
