control 'SV-110349' do
  title 'The Cisco switch must have Storm Control configured on all host-facing switchports.'
  desc 'A traffic storm occurs when packets flood a LAN, creating excessive traffic and degrading network performance. Traffic storm control prevents network disruption by suppressing ingress traffic when the number of packets reaches a configured threshold levels. Traffic storm control monitors ingress traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on all host-facing interfaces as shown in the example below:

interface GigabitEthernet0/3
 switchport access vlan 12
 storm-control unicast unicast level 50.00
 storm-control broadcast broadcast level 40

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each host-facing interface as shown in the example below:

SW1(config)#int range e0/2 – 8
SW1(config-if-range)# storm-control unicast level 50
SW1(config-if-range)# storm-control broadcast level 40'
  impact 0.3
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100125r1_chk'
  tag severity: 'low'
  tag gid: 'V-101245'
  tag rid: 'SV-110349r1_rule'
  tag stig_id: 'CISC-L2-000160'
  tag gtitle: 'SRG-NET-000512-L2S-000001'
  tag fix_id: 'F-106949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
