control 'SV-88807' do
  title 'The Cisco IOS XE router must have IP source routing disabled.'
  desc 'Source routing is a feature of IP, whereby individual packets can specify routes. This feature is used in several different network attacks by bypassing perimeter and internal defense mechanisms.'
  desc 'check', 'Review the configuration of the Cisco IOS XE router to determine if source routing is enabled.

If "ip source-routing" is in the configuration then it is enabled, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to disable IP source routing, using the command below:

ISR4000(config)#no ip source-route'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74219r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74133'
  tag rid: 'SV-88807r2_rule'
  tag stig_id: 'CISR-RT-000020'
  tag gtitle: 'SRG-NET-000195-RTR-000084'
  tag fix_id: 'F-80675r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
