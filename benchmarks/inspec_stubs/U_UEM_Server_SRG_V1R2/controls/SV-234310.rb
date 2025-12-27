control 'SV-234310' do
  title 'The UEM server must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. 

Satisfies:FMT_SMF.1(2)b. 
Reference:PP-MDM-431028'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server enforces the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

If the UEM server does not enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37495r617396_chk'
  tag severity: 'medium'
  tag gid: 'V-234310'
  tag rid: 'SV-234310r879546_rule'
  tag stig_id: 'SRG-APP-000065-UEM-000036'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-37460r613941_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
