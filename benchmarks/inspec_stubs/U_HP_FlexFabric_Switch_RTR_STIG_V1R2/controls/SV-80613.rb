control 'SV-80613' do
  title 'The HP FlexFabric Switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or by botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Interview the system administrator to determine the requirements for bandwidth and traffic prioritization. Display the HP FlexFabric Switch configuration to ensure that the HP FlexFabric Switch is configured with these requirements.

If excess bandwidth is not managed to limit the effects of packet flooding types of denial of service (DoS) attacks, this is a finding 

[HP] display current interface serial10/0
#
interface Serial10/0
 description IUT 2M-SERIAL
 virtualbaudrate 2048000
 qos reserved-bandwidth pct 100
 qos flow-interval 1
 qos apply policy JITC-2M-SERIAL outbound
 undo ipv6 nd ra halt
#'
  desc 'fix', 'Implement a mechanism for traffic prioritization and bandwidth reservation. This mechanism must enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

traffic classifier VOICE operator or
 if-match dscp 49
#
traffic behavior VOICE-2M-SERIAL
 traffic-policy NEST_EF
 gts cir 441 cbs 2757 ebs 0 queue-length 50
 queue ef bandwidth pct 25 cbs-ratio 25
#
traffic classifier VIDEO operator or
 if-matdscp 39
#
traffic behavior VIDEO-2M-SERIAL
 traffic-policy NEST_AF
 gts cir 301 cbs 1882 ebs 0 queue-length 50
 queue af bandwidth pct 15
#
traffic classifier DATA operator or
 if-match dscp 11
#
traffic behavior DATA-2M-SERIAL
 traffic-policy NEST_AF
 gts cir 778 cbs 4863 ebs 0 queue-length 50
 queue af bandwidth pct 40
#
qos policy JITC-2M-SERIAL
 classifier default-class behavior be-bal
 classifier VOICE behavior VOICE-2M-SERIAL
 classifier VIDEO behavior VIDEO-2M-SERIAL
 classifier DATA behavior DATA-2M-SERIAL
#
interface Serial10/0
 description IUT 2M-SERIAL
 virtualbaudrate 2048000
 qos reserved-bandwidth pct 100
 qos flow-interval 1
 qos apply policy JITC-2M-SERIAL outbound
 undo ipv6 nd ra halt'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66123'
  tag rid: 'SV-80613r2_rule'
  tag stig_id: 'HFFS-RT-000018'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-72199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
