control 'SV-220636' do
  title 'The Cisco switch must have Storm Control configured on all host-facing switchports.'
  desc 'A traffic storm occurs when packets flood a LAN, creating excessive traffic and degrading network performance. Traffic storm control prevents network disruption by suppressing ingress traffic when the number of packets reaches a configured threshold levels. 

Traffic storm control monitors ingress traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on all host-facing interfaces as shown in the example below:

interface GigabitEthernet0/3
switchport access vlan 12
storm-control unicast level bps 62000000
storm-control broadcast level bps 20000000

Note: Bandwidth percentage thresholds (via level parameter) can be used in lieu of PPS rate.

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each host-facing interface as shown in the example below:

SW1(config)#int range g0/2 - 8 
SW1(config-if-range)#storm-control unicast bps 62000000 
SW1(config-if-range)#storm-control broadcast level bps 20000000 


Note: The acceptable range is 10000000 -1000000000 for a gigabit Ethernet interface, and 100000000-10000000000 for a 10-gigabit interface. Storm control is not supported on most FastEthernet interfaces.'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22351r648761_chk'
  tag severity: 'low'
  tag gid: 'V-220636'
  tag rid: 'SV-220636r648763_rule'
  tag stig_id: 'CISC-L2-000160'
  tag gtitle: 'SRG-NET-000512-L2S-000001'
  tag fix_id: 'F-22340r648762_fix'
  tag 'documentable'
  tag legacy: ['SV-110243', 'V-101139']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
