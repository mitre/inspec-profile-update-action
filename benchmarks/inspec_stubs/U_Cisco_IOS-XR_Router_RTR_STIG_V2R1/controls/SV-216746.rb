control 'SV-216746' do
  title 'The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the configuration to verify the ipv4 unreachables disable command has been configured on all external interfaces as shown in the configuration example below.

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 unreachables disable 

Note: ICMP unreachables must also be configured. On the Null0 interface if it is used to black hole traffic.

If ICMP unreachable notifications are sent from any external or Null0 interface, this is a finding.

Alternative – DODIN Backbone 

Verify that the PE router is configured to rate limit ICMP unreachable messages as shown in the example below.

ip icmp ipv4 rate-limit unreachable 60000
ip icmp ipv4 rate-limit unreachable DF 1000

Note: In the example above, packet-too-big message (ICMP Type 3 Code 4) can be sent once every second, while all other destination unreachable messages can be sent once every minute. This will avoid disrupting Path MTU Discovery for traffic traversing the backbone while mitigating the risk of an ICMP unreachable denial of service attack.

IF the PE router is not configured to rate limit ICMP unreachable messages, this is a finding.'
  desc 'fix', 'Disable ip unreachables on all external interfaces as shown below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1
RP/0/0/CPU0:R3(config-if)#ipv4 unreachables disable 

Alternative – DODIN Backbone 

Configure the PE router to rate limit ICMP unreachable messages as shown in the example below.

RP/0/0/CPU0:R3(config)#icmp ipv4 rate-limit unreachable df 1000
RP/0/0/CPU0:R3(config)#icmp ipv4 rate-limit unreachable 60000
RP/0/0/CPU0:R3(config)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17978r288627_chk'
  tag severity: 'medium'
  tag gid: 'V-216746'
  tag rid: 'SV-216746r531087_rule'
  tag stig_id: 'CISC-RT-000170'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag fix_id: 'F-17976r288628_fix'
  tag 'documentable'
  tag legacy: ['SV-105837', 'V-96699']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
