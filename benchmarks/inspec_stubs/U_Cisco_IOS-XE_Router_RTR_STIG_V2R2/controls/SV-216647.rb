control 'SV-216647' do
  title 'The Cisco router must be configured to have all non-essential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to verify that the router does not have any unnecessary or non-secure services enabled. For example, the following commands should not be in the configuration:

boot network
ip boot server
ip bootp server
ip dns server
ip identd
ip finger
ip http server
ip rcmd rcp-enable
ip rcmd rsh-enable
service config
service finger
service tcp-small-servers
service udp-small-servers
service pad

If any unnecessary services are enabled, this is a finding.'
  desc 'fix', 'Disable the following services if enabled as shown in the example below:

R2(config)#no boot network
R2(config)#no ip boot server
R2(config)#no ip bootp server
R2(config)#no ip dns server
R2(config)#no ip identd
R2(config)#no ip finger
R2(config)#no ip http server
R2(config)#no ip rcmd rcp-enable
R2(config)#no ip rcmd rsh-enable
R2(config)#no service config
R2(config)#no service finger
R2(config)#no service tcp-small-servers
R2(config)#no service udp-small-servers
R2(config)#no service pad'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17880r287901_chk'
  tag severity: 'low'
  tag gid: 'V-216647'
  tag rid: 'SV-216647r531086_rule'
  tag stig_id: 'CISC-RT-000070'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-17878r287902_fix'
  tag 'documentable'
  tag legacy: ['SV-106005', 'V-96867']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
