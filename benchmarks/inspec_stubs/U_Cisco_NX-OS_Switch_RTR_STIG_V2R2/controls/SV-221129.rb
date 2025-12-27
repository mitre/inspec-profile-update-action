control 'SV-221129' do
  title 'The Cisco PE switch must be configured to enforce a Quality-of-Service (QoS) policy in accordance with the QoS GIG Technical Profile.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the switch configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications in accordance with the QoS DoDIN Technical Profile. 

Step 1: Verify that the class-maps are configured to match on DSCP values as shown in the configuration example below:

class-map match-all C2_VOICE
 match ip dscp af47
class-map match-all VOICE
 match ip dscp ef
class-map match-all VIDEO
 match ip dscp af41
class-map match-all CONTROL_PLANE
 match ip dscp cs6
class-map match-all PREFERRED_DATA
 match ip dscp af33

Step 2: Verify that the policy map reserves the bandwidth for each traffic type as shown in the example below:

policy-map QOS_POLICY
class C2_VOICE
 priority percent 10
 class VOICE
 priority percent 15
 class VIDEO
 bandwidth percent 25
class CONTROL_PLANE
 priority percent 10
 class PREFERRED_DATA
 bandwidth percent 25
 class class-default
 bandwidth percent 15

Step 3: Verify that an output service policy is bound to all interface as shown in the configuration example below:

interface Ethernet1/1
 ip address 10.1.15.1/30
 service-policy output QOS_POLICY
!
interface Ethernet1/2
 ip address 10.1.15.4/30
 service-policy output QOS_POLICY

Note: Enclaves must mark or re-mark their traffic to be consistent with the DoDIN backbone admission criteria to gain the appropriate level of service. A general DiffServ principle is to mark or trust traffic as close to the source as administratively and technically possible. However, certain traffic types might need to be re-marked before handoff to the DoDIN backbone to gain admission to the correct class. If such re-marking is required, it is recommended that the re-marking be performed at the CE egress edge.

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link: 
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List

If the switch is not configured to enforce a QoS policy in accordance with the QoS GIG Technical Profile, this is a finding.'
  desc 'fix', 'Configure a QoS policy in accordance with the QoS GIG Technical Profile.

Step 1: Configure class-maps to match on DSCP values as shown in the configuration example below:

SW1(config-cmap)# class-map match-all C2_VOICE
SW1(config-cmap)# match ip dscp 47
SW1(config-cmap)# class-map match-all VOICE
SW1(config-cmap)# match ip dscp ef
SW1(config-cmap)# class-map match-all VIDEO
SW1(config-cmap)# match ip dscp af41
SW1(config-cmap)# class-map match-all CONTROL_PLANE
SW1(config-cmap)# match ip dscp cs6
SW1(config-cmap)# class-map match-all PREFERRED_DATA
SW1(config-cmap)# match ip dscp af33
SW1(config-cmap)# exit

Step 2: Configure a policy map to be applied to the interfaces that reserves the bandwidth for each traffic type as shown in the example below:

SW1(config)# policy-map QOS_POLICY
SW1(config-pmap-c)# class C2_VOICE
SW1(config-pmap-c)# priority percent 10
SW1(config-pmap-c)# class VOICE
SW1(config-pmap-c)# priority percent 15
SW1(config-pmap-c)# class VIDEO
SW1(config-pmap-c)# bandwidth percent 25
SW1(config-pmap)# class CONTROL_PLANE
SW1(config-pmap-c)# priority percent 10
SW1(config-pmap-c)# class PREFERRED_DATA
SW1(config-pmap-c)# bandwidth percent 25
SW1(config-pmap-c)# class class-default
SW1(config-pmap-c)# bandwidth percent 15
SW1(config-pmap-c)# exit
SW1(config-pmap)# exit

Step 3: Apply the output service policy to all interfaces as shown in the configuration example below:

SW1(config)# int e1/1
SW1(config-if)# service-policy output QOS_POLICY
SW1(config-if)# exit
SW1(config)# int e1/2
SW1(config-if)# service-policy output QOS_POLICY
SW1(config-if)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22844r409876_chk'
  tag severity: 'low'
  tag gid: 'V-221129'
  tag rid: 'SV-221129r622190_rule'
  tag stig_id: 'CISC-RT-000760'
  tag gtitle: 'SRG-NET-000193-RTR-000113'
  tag fix_id: 'F-22833r409877_fix'
  tag 'documentable'
  tag legacy: ['SV-111077', 'V-101973']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
