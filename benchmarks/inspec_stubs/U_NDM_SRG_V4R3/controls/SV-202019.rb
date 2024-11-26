control 'SV-202019' do
  title 'The network device must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review the device configuration to verify that it enforces the limit of three consecutive invalid logon attempts.

If the device is not configured to enforce the limit of three consecutive invalid logon attempts, this is a finding.'
  desc 'fix', 'Configure the network device to enforce the limit of three consecutive invalid logon attempts during a 15-minute time period.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2145r381587_chk'
  tag severity: 'medium'
  tag gid: 'V-202019'
  tag rid: 'SV-202019r879546_rule'
  tag stig_id: 'SRG-APP-000065-NDM-000214'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-2146r381588_fix'
  tag 'documentable'
  tag legacy: ['SV-69301', 'V-55055']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
