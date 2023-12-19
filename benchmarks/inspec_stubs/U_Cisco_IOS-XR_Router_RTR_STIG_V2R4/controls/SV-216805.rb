control 'SV-216805' do
  title 'The Cisco P router must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications.

Step 1: Verify that the class-maps are configured to match on DSCP values as shown in the configuration example below.

class-map match-all VIDEO
 match dscp af41 
 end-class-map
! 
class-map match-all VOICE
 match dscp ef 
 end-class-map
! 
class-map match-all C2_VOICE
 match dscp 47 
 end-class-map
! 
class-map match-all CONTROL_PLANE
 match dscp cs6 
 end-class-map
! 
class-map match-all PREFERRED_DATA
 match dscp af33 
 end-class-map
!

Step 2: Verify that the policy map reserves the bandwidth for each traffic type as shown in the following example:

policy-map QOS_POLICY
 class C2_VOICE
  bandwidth percent 10 
 ! 
 class VOICE
  bandwidth percent 15 
 ! 
 class VIDEO
  bandwidth percent 25 
 ! 
 class CONTROL_PLANE
  bandwidth percent 10 
 ! 
 class PREFERRED_DATA
  bandwidth percent 25 
 ! 
 class class-default
  bandwidth percent 15 
 ! 
 end-policy-map
!

Step 3: Verify that an output service policy is bound to all interfaces as shown in the configuration example below.

interface GigabitEthernet0/0/0/1
 service-policy output QOS_POLICY
 ipv4 address x.1.24.2 255.255.255.252
!
interface GigabitEthernet0/0/0/2
 service-policy output QOS_POLICY
ipv4 address x.1.24.5 255.255.255.252

Note: Enclaves must mark or re-mark their traffic to be consistent with the DODIN backbone admission criteria to gain the appropriate level of service. A general DiffServ principle is to mark or trust traffic as close to the source as administratively and technically possible. However, certain traffic types might need to be re-marked before handoff to the DODIN backbone to gain admission to the correct class. If such re-marking is required, it is recommended that the re-marking be performed at the CE egress edge.

If the router is not configured to enforce a QoS policy in accordance with the QoS DODIN Technical Profile, this is a finding.'
  desc 'fix', 'Configure to enforce a QoS policy to provide preferred treatment for mission-critical applications.

Step 1: Configure class-maps to match on DSCP values as shown in the configuration example below.

RP/0/0/CPU0:R2(config-cmap)#class-map match-all C2_VOICE
RP/0/0/CPU0:R2(config-cmap)#match dscp 47
RP/0/0/CPU0:R2(config-cmap)#class-map match-all VOICE
RP/0/0/CPU0:R2(config-cmap)#match dscp ef
RP/0/0/CPU0:R2(config-cmap)#class-map match-all VIDEO
RP/0/0/CPU0:R2(config-cmap)#match dscp af41
RP/0/0/CPU0:R2(config-cmap)#class-map match-all CONTROL_PLANE
RP/0/0/CPU0:R2(config-cmap)#match dscp cs6
RP/0/0/CPU0:R2(config-cmap)#class-map match-all PREFERRED_DATA
RP/0/0/CPU0:R2(config-cmap)#match dscp af33
RP/0/0/CPU0:R2(config-cmap)#exit

Step 2: Configure a policy map to be applied to the core-layer-facing interface that  reserves the bandwidth for each traffic type as shown in the example below.

RP/0/0/CPU0:R2(config-pmap)#policy-map QOS_POLICY
RP/0/0/CPU0:R2(config-pmap)#class C2_VOICE
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 10
RP/0/0/CPU0:R2(config-pmap-c)#class VOICE
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 15
RP/0/0/CPU0:R2(config-pmap-c)#class VIDEO
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 25
RP/0/0/CPU0:R2(config-pmap-c)#class CONTROL_PLANE
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 10
RP/0/0/CPU0:R2(config-pmap-c)#class PREFERRED_DATA
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 25
RP/0/0/CPU0:R2(config-pmap-c)#class class-default
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 15
RP/0/0/CPU0:R2(config-pmap-c)#exit

Step 3: Apply the output service policy to the core-layer-facing interface as shown in the configuration example below.

RP/0/0/CPU0:R2(config)#int g0/0/0/1
RP/0/0/CPU0:R2(config-if)#service-policy output QOS_POLICY 
RP/0/0/CPU0:R2(config-if)#exit
RP/0/0/CPU0:R2(config)#int g0/0/0/2                     
RP/0/0/CPU0:R2(config-if)#service-policy output QOS_POLICY 
RP/0/0/CPU0:R2(config-if)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18037r917440_chk'
  tag severity: 'low'
  tag gid: 'V-216805'
  tag rid: 'SV-216805r917442_rule'
  tag stig_id: 'CISC-RT-000770'
  tag gtitle: 'SRG-NET-000193-RTR-000114'
  tag fix_id: 'F-18035r917441_fix'
  tag 'documentable'
  tag legacy: ['SV-105955', 'V-96817']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
