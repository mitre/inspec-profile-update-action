control 'SV-88647' do
  title 'The Cisco IOS XE router must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review the Cisco router configuration to verify that it enforces the limit of three consecutive invalid logon attempts within a fifteen-minute period as shown in the example below.

login block-for 600 attempts 3 within 900

Note: The configuration example above will block any logon attempt for 10 minutes after three consecutive invalid logon attempts.

If the Cisco router is not configured to enforce the limit of three consecutive invalid logon attempts within a fifteen-minute period, this is a finding.'
  desc 'fix', 'Configure the Cisco router to enforce the limit of three consecutive invalid logon attempts within a fifteen-minute period as shown in the example below.

login block-for 600 attempts 3 within 900'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74055r6_chk'
  tag severity: 'medium'
  tag gid: 'V-73973'
  tag rid: 'SV-88647r3_rule'
  tag stig_id: 'CISR-ND-000015'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-80513r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
