control 'SV-216798' do
  title 'The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the router configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS as shown in the example below.

bridge group L2GROUP
  bridge-domain L2_BRIDGE_COI1
   interface GigabitEthernet0/0/0/2
    storm-control unknown-unicast kbps 1200
    storm-control multicast kbps 1200
    storm-control broadcast kbps 1200
    split-horizon group
   !

If storm control is not enabled at a minimum for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each CE-facing interface as shown in the example below.

RP/0/0/CPU0:R3(config)#l2vpn
RP/0/0/CPU0:R3(config-l2vpn)#bridge group L2GROUP
RP/0/0/CPU0:R3(config-l2vpn-bg)# bridge-domain L2_BRIDGE_COI1
RP/0/0/CPU0:R3(config-l2vpn-bg-bd)#interface GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#storm-control broadcast kbps 1200
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#storm-control multicast kbps 1200
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#storm-control unknown-unicast kbps 1200
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#end

Note: The acceptable range is 10000000 -1000000000 for a gigabit ethernet interface, and 100000000-10000000000 for a ten gigabit interface. Storm control is not supported on most FastEthernet interfaces.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18030r288771_chk'
  tag severity: 'medium'
  tag gid: 'V-216798'
  tag rid: 'SV-216798r531087_rule'
  tag stig_id: 'CISC-RT-000700'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-18028r288772_fix'
  tag 'documentable'
  tag legacy: ['SV-105941', 'V-96803']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
