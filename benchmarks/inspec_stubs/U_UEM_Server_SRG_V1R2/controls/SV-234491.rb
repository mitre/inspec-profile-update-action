control 'SV-234491' do
  title 'The UEM server must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431030'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server automatically locks the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.

If the UEM server does not automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37676r851554_chk'
  tag severity: 'medium'
  tag gid: 'V-234491'
  tag rid: 'SV-234491r879722_rule'
  tag stig_id: 'SRG-APP-000345-UEM-000218'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-37641r615117_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
