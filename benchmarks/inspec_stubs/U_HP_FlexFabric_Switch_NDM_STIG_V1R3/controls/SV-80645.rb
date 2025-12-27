control 'SV-80645' do
  title 'The HP FlexFabric Switch must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify that the HP FlexFabric Switch is configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

[HP] display password-control

Global password control configurations:
 Maximum login attempts:              3
 Action for exceeding login attempts: Lock user for 15 minutes

If the limit of three consecutive invalid logon attempts by a user during a 15-minute time period is not enforced, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period:

[HP]password-control login-attempt 3 exceed lock-time 15'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66155'
  tag rid: 'SV-80645r1_rule'
  tag stig_id: 'HFFS-ND-000015'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-72231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
