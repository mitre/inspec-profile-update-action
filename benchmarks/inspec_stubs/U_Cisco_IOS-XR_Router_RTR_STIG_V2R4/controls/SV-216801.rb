control 'SV-216801' do
  title 'The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as Layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all routers at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Step 1: Review the router configuration to verify that an ingress ACL is applied to all external or CE-facing interfaces. 

interface GigabitEthernet1/1/0/0
 ipv4 address x.1.12.2 255.255.255.252
 ipv4 access-group BLOCK_TO_CORE ingress

Step 2: Verify that the ingress ACL discards and logs packets destined to the IP core address space. 

Ipv4 access-list BLOCK_TO_CORE
  10 deny ipv4 any 10.1.x.0 0.0.255.255 log-input
  20 permit ipv4 any any
!

If the PE router is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent neighbors.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Step 1: Configure an ingress ACL to discard and log packets destined to the IP core address space. 

RP/0/0/CPU0:R3(config)#Ipv4 access-list BLOCK_TO_CORE
RP/0/0/CPU0:R3(config-ipv4-acl)#deny tcp any any eq tacacs log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ipv4 any 10.1.x.0 0.0.255.255 log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#end

Step 2: Apply the ACL inbound to all external or CE-facing interfaces.

RP/0/0/CPU0:R3(config)#int g1/1/0/0
RP/0/0/CPU0:R3(config-if)#ipv4 access-group BLOCK_TO_CORE in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18033r288780_chk'
  tag severity: 'high'
  tag gid: 'V-216801'
  tag rid: 'SV-216801r531087_rule'
  tag stig_id: 'CISC-RT-000730'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-18031r288781_fix'
  tag 'documentable'
  tag legacy: ['SV-105947', 'V-96809']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
