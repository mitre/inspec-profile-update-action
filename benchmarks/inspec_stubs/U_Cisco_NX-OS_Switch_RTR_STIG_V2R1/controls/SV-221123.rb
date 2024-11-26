control 'SV-221123' do
  title 'The Cisco PE switch providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS as shown in the example below:

interface Ethernet2/4
 no shutdown
 no switchport
 storm-control broadcast level 40.00
 service instance 1 ethernet
 encapsulation dot1q 100

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each CE-facing interface as shown in the example below:

SW1(config)# int e2/4
SW1(config-if)# storm-control broadcast level 40 
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22838r409858_chk'
  tag severity: 'medium'
  tag gid: 'V-221123'
  tag rid: 'SV-221123r622190_rule'
  tag stig_id: 'CISC-RT-000700'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-22827r409859_fix'
  tag 'documentable'
  tag legacy: ['SV-111065', 'V-101961']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
