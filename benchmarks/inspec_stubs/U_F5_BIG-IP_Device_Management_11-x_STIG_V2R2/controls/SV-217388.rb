control 'SV-217388' do
  title 'The BIG-IP appliance must be configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

If the BIG-IP appliance is not configure to use a remote authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18613r290718_chk'
  tag severity: 'medium'
  tag gid: 'V-217388'
  tag rid: 'SV-217388r879546_rule'
  tag stig_id: 'F5BI-DM-000031'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-18611r290719_fix'
  tag 'documentable'
  tag legacy: ['SV-74543', 'V-60113']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
