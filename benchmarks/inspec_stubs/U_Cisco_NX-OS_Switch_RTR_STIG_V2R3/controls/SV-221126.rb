control 'SV-221126' do
  title 'The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as Layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all switches at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Step 1: Review the switch configuration to verify that an ingress ACL is applied to all external or CE-facing interfaces. 

interface Ethernet1/2
 ip address x.1.12.2/30
 ip access-group BLOCK_TO_CORE in

Step 2: Verify that the ingress ACL discards and logs packets destined to the IP core address space. 

ip access-list BLOCK_TO_CORE
 deny ip any 10.1.x.0 0.0.255.255 log
 permit ip any any

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent neighbors.

If the PE switch is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Step 1: Configure an ingress ACL to discard and log packets destined to the IP core address space. 

SW1(config)# ip access-list BLOCK_TO_CORE
SW1(config-acl)# deny ip any 10.1.x.0 0.0.255.255 log
SW1(config-acl)# exit

Step 2: Apply the ACL inbound to all external or CE-facing interfaces.

SW1(config)#int e1/2
SW1(config-if)# ip access-group BLOCK_TO_CORE in
SW1(config-if)# end'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22841r409867_chk'
  tag severity: 'high'
  tag gid: 'V-221126'
  tag rid: 'SV-221126r622190_rule'
  tag stig_id: 'CISC-RT-000730'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-22830r409868_fix'
  tag 'documentable'
  tag legacy: ['SV-111071', 'V-101967']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
