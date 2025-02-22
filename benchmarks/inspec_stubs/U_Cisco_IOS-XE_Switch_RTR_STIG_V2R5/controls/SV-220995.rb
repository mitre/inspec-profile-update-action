control 'SV-220995' do
  title 'The Cisco switch must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.'
  desc 'The Route Processor (RP) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the RP or the control and management planes can result in mission-critical network outages.

A DoS attack targeting the RP can result in excessive CPU and memory utilization. To maintain network stability and RP security, the router must be able to handle specific control plane and management plane traffic that is destined to the RP. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic, as well as limiting traffic destined to the device. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grows. Control plane policing increases the security of routers and multilayer switches by protecting the RP from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Review the Cisco switch configuration to verify it protects against known types of DoS attacks by employing organization-defined security safeguards. 

Step 1: Verify traffic types have been classified based on importance levels. The following is an example configuration: 

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

Step 2: Review the access control lists (ACLs) referenced by the class maps to determine if the traffic is being classified appropriately. The following is an example configuration: 

ip access-list extended CoPP_CRITICAL 
remark our control plane adjacencies are critical 
permit ospf host [OSPF neighbor A] any 
permit ospf host [OSPF neighbor B] any 
permit pim host [PIM neighbor A] any 
permit pim host [PIM neighbor B] any 
permit pim host [RP addr] any 
permit igmp any 224.0.0.0 15.255.255.255 
deny ip any any 

ip access-list extended CoPP_IMPORTANT 
permit tcp host [TACACS server] eq tacacs any 
permit tcp [management subnet] 0.0.0.255 any eq 22 
permit udp host [SNMP manager] any eq snmp 
permit udp host [NTP server] eq ntp any 
deny ip any any 

ip access-list extended CoPP_NORMAL 
remark we will want to rate limit ICMP traffic 
deny icmp any host x.x.x.x fragments
permit icmp any any echo 
permit icmp any any echo-reply 
permit icmp any any time-exceeded 
permit icmp any any unreachable 
deny ip any any 

ip access-list extended CoPP_UNDESIRABLE 
remark other management plane traffic that should not be received 
permit udp any any eq ntp 
permit udp any any eq snmp 
permit tcp any any eq 22 
permit tcp any any eq 23 
remark other control plane traffic not configured on switch 
permit eigrp any any 
permit udp any any eq rip 
deny ip any any 

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
class CoPP_DEFAULT 
police 64000 1000 conform-action transmit exceed-action drop 

Step 4: Verify that the Control Plane Policing (CoPP) policy is enabled. The following is an example configuration: 

control-plane 
service-policy input CONTROL_PLANE_POLICY 

Note: Control Plane Protection (CPPr) can be used to filter as well as police control plane traffic destined to the RP. CPPr is very similar to CoPP and has the ability to filter and police traffic using finer granularity by dividing the aggregate control plane into three separate categories: 1) host, 2) transit, and 3) CEF-exception. Hence, a separate policy-map could be configured for each traffic category. 

If the Cisco switch is not configured to protect against known types of DoS attacks by employing organization-defined security safeguards, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to protect against known types of DoS attacks on the route processor. Implementing a CoPP policy as shown in the example below is a best practice method: 

Step 1: Configure ACL specific traffic types. 

SW1(config)#ip access-list extended CoPP_CRITICAL 
SW1(config-ext-nacl)#remark our control plane adjacencies are critical 
SW1(config-ext-nacl)#permit ospf host x.x.x.x any 
SW1(config-ext-nacl)#permit ospf host x.x.x.x any 
SW1(config-ext-nacl)#permit pim host x.x.x.x any 
SW1(config-ext-nacl)#permit pim host x.x.x.x any 
SW1(config-ext-nacl)#permit igmp any 224.0.0.0 15.255.255.255 
SW1(config-ext-nacl)#deny ip any any 
SW1(config-ext-nacl)#exit 

SW1(config)#ip access-list extended CoPP_IMPORTANT 
SW1(config-ext-nacl)#permit tcp host x.x.x.x eq tacacs any 
SW1(config-ext-nacl)#permit tcp x.x.x.x 0.0.0.255 any eq 22 
SW1(config-ext-nacl)#permit udp host x.x.x.x any eq snmp 
SW1(config-ext-nacl)#permit udp host x.x.x.x eq ntp any 
SW1(config-ext-nacl)#deny ip any any 
SW1(config-ext-nacl)#exit 

SW1(config)#ip access-list extended CoPP_NORMAL 
SW1(config-ext-nacl)#remark we will want to rate limit ICMP traffic 
SW1(config-ext-nacl)#deny icmp any host x.x.x.x fragments
 SW1(config-ext-nacl)#permit icmp any any echo 
SW1(config-ext-nacl)#permit icmp any any echo-reply 
SW1(config-ext-nacl)#permit icmp any any time-exceeded 
SW1(config-ext-nacl)#permit icmp any any unreachable 
SW1(config-ext-nacl)#deny ip any any 
SW1(config-ext-nacl)#exit 

SW1(config)#ip access-list extended CoPP_UNDESIRABLE 
SW1(config-ext-nacl)#remark management plane traffic that should not be received 
SW1(config-ext-nacl)#permit udp any any eq ntp 
SW1(config-ext-nacl)#permit udp any any eq snmp 
SW1(config-ext-nacl)#permit tcp any any eq 22 
SW1(config-ext-nacl)#permit tcp any any eq 23 
SW1(config-ext-nacl)#remark control plane traffic not configured on switch 
SW1(config-ext-nacl)#permit eigrp any any 
SW1(config-ext-nacl)#permit udp any any eq rip 
SW1(config-ext-nacl)#deny ip any any 
SW1(config-ext-nacl)#exit 
SW1(config)#ip access-list extended CoPP_DEFAULT 
SW1(config-ext-nacl)#permit ip any any 
SW1(config-ext-nacl)#exit 

Step 2: Configure class-maps referencing each of the ACLs. 

SW1(config)#class-map match-all CoPP_CRITICAL 
SW1(config-cmap)#match access-group name CoPP_CRITICAL 
SW1(config-cmap)#class-map match-any CoPP_IMPORTANT 
SW1(config-cmap)#match access-group name CoPP_IMPORTANT 
SW1(config-cmap)#match protocol arp 
SW1(config-cmap)#class-map match-all CoPP_NORMAL 
SW1(config-cmap)#match access-group name CoPP_NORMAL 
SW1(config-cmap)#class-map match-any CoPP_UNDESIRABLE 
SW1(config-cmap)#match access-group name CoPP_UNDESIRABLE 
SW1(config-cmap)#class-map match-all CoPP_DEFAULT 
SW1(config-cmap)#match access-group name CoPP_DEFAULT 
SW1(config-cmap)#exit 

Step 3: Configure a policy-map referencing the configured class-maps and apply appropriate bandwidth allowance and policing attributes. 

SW1(config)#policy-map CONTROL_PLANE_POLICY 
SW1(config-pmap)#class CoPP_CRITICAL 
SW1(config-pmap-c)#police 512000 8000 conform-action transmit exceed-action transmit 
SW1(config-pmap-c-police)#class CoPP_IMPORTANT 
SW1(config-pmap-c)#police 256000 4000 conform-action transmit exceed-action drop 
SW1(config-pmap-c-police)#class CoPP_NORMAL 
SW1(config-pmap-c)#police 128000 2000 conform-action transmit exceed-action drop 
SW1(config-pmap-c-police)#class CoPP_UNDESIRABLE 
SW1(config-pmap-c)#police 8000 1000 conform-action drop exceed-action drop 
SW1(config-pmap-c-police)#class CoPP_DEFAULT 
SW1(config-pmap-c)#police 64000 1000 conform-action transmit exceed-action drop 
SW1(config-pmap-c-police)#exit 
SW1(config-pmap-c)#exit 
SW1(config-pmap)#exit 

Step 4: Apply the policy-map to the control plane. 

SW1(config)#control-plane 
SW1(config-cp)#service-policy input CONTROL_PLANE_POLICY 
SW1(config-cp)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22710r929065_chk'
  tag severity: 'high'
  tag gid: 'V-220995'
  tag rid: 'SV-220995r929067_rule'
  tag stig_id: 'CISC-RT-000120'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-22699r929066_fix'
  tag 'documentable'
  tag legacy: ['SV-110811', 'V-101707']
  tag cci: ['CCI-002385', 'CCI-001097']
  tag nist: ['SC-5 a', 'SC-7 a']
end
