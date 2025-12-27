control 'SV-80363' do
  title 'Trend Deep Security must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the limit of three consecutive invalid logon attempts by a user during a 15-minute time period is enforced.

Verify the number of failed logon attempts. Go to Administration >> System Settings >> Security >> User Security >> Number of incorrect sign-in attempts allowed (before lock out): 3

If the number is greater than 3 this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

Configure the number of failed logon attempts to 3.

Administration >> System Settings >> Security >> User Security >> Number of incorrect sign-in attempts allowed (before lock out): 3'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66521r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65873'
  tag rid: 'SV-80363r1_rule'
  tag stig_id: 'TMDS-00-000050'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-71949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
