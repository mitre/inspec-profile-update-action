control 'SV-220557' do
  title 'The Cisco switch must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (e.g., firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. 

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

Step 2: Review the ACLs referenced by the class maps to determine if the traffic is being classified appropriately. The following is an example configuration: 

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

ip access-list extended CoPP_IMPORTANT 
permit tcp host [TACACS server] eq tacacs any 
permit tcp [management subnet] 0.0.0.255 any eq 22 
permit udp host [SNMP manager] any eq snmp 
permit udp host [NTP server] eq ntp any 
deny ip any any 

ip access-list extended CoPP_NORMAL 
remark we will want to rate limit ICMP traffic 
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

Step 4: Verify that the CoPP policy is enabled. The following is an example configuration: 

control-plane 
service-policy input CONTROL_PLANE_POLICY 

Note: Control Plane Protection (CPPr) can be used to filter as well as police control plane traffic destined to the RP. CPPr is very similar to CoPP and has the ability to filter and police traffic using finer granularity by dividing the aggregate control plane into three separate categories: (1) host, (2) transit, and (3) CEF-exception. Hence, a separate policy-map could be configured for each traffic category.

If the Cisco switch is not configured to protect against known types of DoS attacks by employing organization-defined security safeguards, this is a finding.'
  desc 'fix', 'Configure the Cisco switch protect against known types of DoS attacks on the route processor. Implementing a CoPP policy as shown in the example below is a best practice method.

Step 1: Configure ACLs specific traffic types.

SW1(config)#ip access-list extended CoPP_CRITICAL
SW1(config-ext-nacl)#remark our control plane adjacencies are critical
SW1(config-ext-nacl)#permit ospf host x.x.x.x any
SW1(config-ext-nacl)#permit ospf host x.x.x.x any
SW1(config-ext-nacl)#permit pim host x.x.x.x any
SW1(config-ext-nacl)#permit pim host x.x.x.x any
SW1(config-ext-nacl)#permit igmp any 224.0.0.0 15.255.255.255
SW1(config-ext-nacl)#permit tcp host x.x.x.x eq bgp host x.x.x.x
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

Step 2: Configure class maps referencing each of the ACLs.

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

Step 3: Configure a policy map referencing the configured class maps and apply appropriate bandwidth allowance and policing attributes.

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

Step 4: Apply the policy map to the control plane.

SW1(config)#control-plane
SW1(config-cp)#service-policy input CONTROL_PLANE_POLICY
SW1(config-cp)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22272r508615_chk'
  tag severity: 'medium'
  tag gid: 'V-220557'
  tag rid: 'SV-220557r531084_rule'
  tag stig_id: 'CISC-ND-001220'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-22261r508616_fix'
  tag 'documentable'
  tag legacy: ['SV-110569', 'V-101465']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
