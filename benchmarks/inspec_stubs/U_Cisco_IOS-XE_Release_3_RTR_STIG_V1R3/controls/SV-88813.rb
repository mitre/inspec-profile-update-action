control 'SV-88813' do
  title 'The Cisco IOS XE router must protect against or limit the effects of denial of service (DoS) attacks by employing control plane protection.'
  desc 'The Route Processor (RP) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the Route Processor or the control and management planes can result in mission-critical network outages. 

A DoS attack targeting the Route Processor can result in excessive CPU and memory utilization. To maintain network stability and Route Processor security, the router must be able to handle specific control plane and management plane traffic that is destined to the Route Processor. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grow. Control plane policing increases the security of routers and multilayer switches by protecting the Route Processor from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Step 1: Verify traffic types have been classified based on importance levels.

The following is an example configuration: 

class-map match-all CoPP_CRITICAL 
match access-group name CoPP_CRITICAL 
class-map match-any CoPP_IMPORTANT 
match access-group name CoPP_IMPORTANT 
match protocol arp 
class-map match-all CoPP_NORMAL 
match access-group name CoPP_NORMAL 
class-map match-any CoPP_UNDESIRABLE 
match access-group name CoPP_UNDESIRABLE 
class-map match-all CoPP_DEFAULT 
match access-group name CoPP_DEFAULT 

Step 2: Review the ACLs referenced by the match access-group commands to determine if the traffic is being classified appropriately. The following is an example configuration: 

ip access-list extended CoPP_CRITICAL 
remark our control plane adjacencies are critical 
permit ospf host [OSPF neighbor A] any 
permit ospf host [OSPF neighbor B] any 
permit pim host [PIM neighbor A] any 
permit pim host [PIM neighbor B] any 
permit pim host [RP addr] any 
permit igmp any 224.0.0.0 15.255.255.255 
permit tcp host [BGP neighbor] eq bgp host [local BGP addr] 
permit tcp host [BGP neighbor] host [local BGP addr] eq bgp 
deny ip any any 
!
ip access-list extended CoPP_IMPORTANT 
permit tcp host [TACACS server] eq tacacs any 
permit tcp [management subnet] 0.0.0.255 any eq 22 
permit udp host [SNMP manager] any eq snmp 
permit udp host [NTP server] eq ntp any 
deny ip any any 
!
ip access-list extended CoPP_NORMAL 
remark we will want to rate limit ICMP traffic 
permit icmp any any echo 
permit icmp any any echo-reply 
permit icmp any any time-exceeded 
permit icmp any any unreachable 
deny ip any any 
!
ip access-list extended CoPP_UNDESIRABLE 
remark other management plane traffic that should not be received 
permit udp any any eq ntp 
permit udp any any eq snmptrap 
permit tcp any any eq 22 
permit tcp any any eq 23 
remark other control plane traffic not configured on router 
permit eigrp any any 
permit udp any any eq rip 
deny ip any any 
!
ip access-list extended CoPP_DEFAULT 
permit ip any any 

Note: Explicitly defining undesirable traffic with ACL entries enables the network operator to collect statistics. Excessive ARP packets can potentially monopolize Route Processor resources, starving other important processes. Currently, ARP is the only Layer 2 protocol that can be specifically classified using the match protocol command.  

Step 3: Review the policy-map to determine if the traffic is being policed appropriately for each classification. The following is an example configuration: 

policy-map CONTROL_PLANE_POLICY 
class CoPP_CRITICAL 
police 512000 8000 conform-action transmit exceed-action transmit 
class CoPP_IMPORTANT 
police 256000 4000 conform-action transmit exceed-action drop 
class CoPP_NORMAL 
police 128000 2000 conform-action transmit exceed-action drop 
class CoPP_UNDESIRABLE 
police 8000 1000 conform-action drop exceed-action drop 

Step 4: Verify that the CoPP policy is enabled.

The following is an example configuration: 

control-plane 
service-policy input CONTROL_PLANE_POLICY 

If the Cisco IOS XE router does not have control plane protection implemented, this is a finding.'
  desc 'fix', 'Implement control plane protection by classifying traffic types based on importance and configure filters to restrict and rate limit the traffic directed to and processed by the route processor according to each class.  The configuration would look similar to the one below:

class-map match-any CoPP_UNDESIRABLE
 match access-group name CoPP_UNDESIRABLE
class-map match-any CoPP_IMPORTANT
 match access-group name CoPP_IMPORTANT
 match protocol arp
class-map match-all CoPP_DEFAULT
 match access-group name CoPP_DEFAULT

policy-map CONTROL_PLANE_POLICY
 class CoPP_CRITICAL
  police 512000 8000 conform-action transmit  exceed-action transmit 
 class CoPP_IMPORTANT
  police 256000 4000 conform-action transmit  exceed-action drop 
 class CoPP_NORMAL
  police 128000 2000 conform-action transmit  exceed-action drop 
 class CoPP_UNDESIRABLE
  police 8000 1000 conform-action drop  exceed-action drop 
 class CoPP_DEFAULT
  police 64000 1000 conform-action transmit  exceed-action drop'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74225r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74139'
  tag rid: 'SV-88813r2_rule'
  tag stig_id: 'CISR-RT-000024'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-80681r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
