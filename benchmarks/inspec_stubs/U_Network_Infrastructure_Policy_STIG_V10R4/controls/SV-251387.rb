control 'SV-251387' do
  title 'A Quality of Service (QoS) policy must be implemented to provide preferred treatment for Command and Control (C2) real-time services and control plane traffic.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, packet loss, and availability. To manage the multitude of applications and services, a network requires a Quality of Service (QoS) framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a service policy. Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented to guarantee the required bandwidth for control plane traffic and C2 real-time services during periods of congestion within the JIE WAN IP network.'
  desc 'check', 'Review each router and verify that a QoS policy has been configured to provide preferred treatment for control plane traffic and C2 real-time services.

Step 1: Verify that the class-maps are configured to match on DSCP values that have been set at the edges as shown in the configuration example below:

class-map match-all CONTROL_PLANE
match ip dscp 48
class-map match-all C2_VOICE
match ip dscp 47
class-map match-all VOICE
match ip dscp ef
class-map match-all VIDEO
match ip dscp af4
class-map match-all PREFERRED_DATA
match ip dscp af3

Step 2: Verify that the policy map applied to the core-layer-facing interface reserves the bandwidth for each traffic type as shown in the following example:

policy-map QOS_POLICY
class CONTROL_PLANE
priority percent 10
class C2_VOICE
priority percent 10
class VOICE
priority percent 15
class VIDEO
bandwidth percent 25
class PREFERRED_DATA
bandwidth percent 25
class class-default
bandwidth percent 15

Step 3: Verify that an output service policy is bound to the core-layer-facing interface as shown in the configuration example below:

interface GigabitEthernet1/1
 ip address 10.2.0.2 255.255.255.252
 service-policy output QOS_POLICY

If a QoS policy has not been implemented within the JIE WAN infrastructure to provide assured services for control plane traffic and C2 real-time services, this is a finding.'
  desc 'fix', 'Configure a QoS policy on each router to provide assured services for control plane traffic and C2 real-time services.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54822r806114_chk'
  tag severity: 'low'
  tag gid: 'V-251387'
  tag rid: 'SV-251387r806116_rule'
  tag stig_id: 'NET2005'
  tag gtitle: 'NET2005'
  tag fix_id: 'F-54775r806115_fix'
  tag 'documentable'
  tag legacy: ['V-66363', 'SV-80853']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
