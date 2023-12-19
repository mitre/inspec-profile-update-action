control 'SV-215668' do
  title 'The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review the Cisco router configuration to verify that it enforces the limit of three consecutive invalid logon attempts as shown in the example below.

login block-for 900 attempts 3 within 120

Note: The configuration example above will block any login attempt for 15 minutes after three consecutive invalid logon attempts within a two-minute period.

If the Cisco router is not configured to enforce the limit of three consecutive invalid logon attempts, this is a finding.'
  desc 'fix', 'Configure the Cisco router to enforce the limit of three consecutive invalid logon attempts as shown in the example below.

R2(config)#login block-for 900 attempts 3 within 120'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16862r285966_chk'
  tag severity: 'medium'
  tag gid: 'V-215668'
  tag rid: 'SV-215668r879546_rule'
  tag stig_id: 'CISC-ND-000150'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-16860r285967_fix'
  tag 'documentable'
  tag legacy: ['V-96025', 'SV-105163']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
