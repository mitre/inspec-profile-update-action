control 'SV-221044' do
  title 'The Cisco PE switch providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS as shown in the example below:

interface GigabitEthernet3
 no switchport
 no ip address
 service instance 10 ethernet
 encapsulation untagged
 bridge-domain 100
 storm-control broadcast cir 12000000 
 !
!

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each CE-facing interface as shown in the example below:

SW1(config)#int g3
SW1(config-if)#service instance 10 ethernet 
SW1(config-if-srv)#storm-control broadcast cir 12000000
SW1(config-if-srv)#end

Note: The acceptable range is 10000000 -1000000000 for a gigabit ethernet interface, and 100000000-10000000000 for a ten gigabit interface. Storm control is not supported on most FastEthernet interfaces.'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22759r408926_chk'
  tag severity: 'medium'
  tag gid: 'V-221044'
  tag rid: 'SV-221044r622190_rule'
  tag stig_id: 'CISC-RT-000700'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-22748r408927_fix'
  tag 'documentable'
  tag legacy: ['SV-110909', 'V-101805']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
