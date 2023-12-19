control 'SV-216708' do
  title 'The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the router configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS as shown in the example below:

interface GigabitEthernet3
 no ip address
 service instance 10 ethernet
  encapsulation untagged
  bridge-domain 100
  storm-control broadcast cir 12000000 
 !
!

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each CE-facing interface as shown in the example below:

R1(config)#int g3
R1(config-if)#service instance 10 ethernet 
R1(config-if-srv)#storm-control broadcast cir 12000000
R1(config-if-srv)#end

Note: The acceptable range is 10000000 -1000000000 for a gigabit ethernet interface, and 100000000-10000000000 for a ten gigabit interface. Storm control is not supported on most FastEthernet interfaces.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17941r288069_chk'
  tag severity: 'medium'
  tag gid: 'V-216708'
  tag rid: 'SV-216708r531086_rule'
  tag stig_id: 'CISC-RT-000700'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-17939r288070_fix'
  tag 'documentable'
  tag legacy: ['SV-106127', 'V-96989']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
