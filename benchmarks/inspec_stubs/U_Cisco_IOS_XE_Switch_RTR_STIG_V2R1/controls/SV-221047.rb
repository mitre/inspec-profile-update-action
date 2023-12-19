control 'SV-221047' do
  title 'The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure.'
  desc 'IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all switches at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Step 1: Review the switch configuration to verify that an ingress ACL is applied to all external or CE-facing interfaces. 

interface GigabitEthernet0/2
 no switchport
 ip address x.1.12.2 255.255.255.252
 ip access-group BLOCK_TO_CORE in

Step 2: Verify that the ingress ACL discards and logs packets destined to the IP core address space. 

ip access-list extended BLOCK_TO_CORE
 deny ip any 10.1.x.0 0.0.255.255 log-input
 permit ip any any
!

If the PE switch is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent neighbors.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Step 1: Configure an ingress ACL to discard and log packets destined to the IP core address space.

SW2(config)#ip access-list extended BLOCK_TO_CORE
SW2(config-ext-nacl)#deny ip any 10.1.x.0 0.0.255.255 log-input
SW2(config-ext-nacl)#exit

Step 2: Apply the ACL inbound to all external or CE-facing interfaces.

SW2(config)#int SW1(config)#int g0/2
SW2(config-if)#ip access-group BLOCK_TO_CORE in
SW2(config-if)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22762r408935_chk'
  tag severity: 'high'
  tag gid: 'V-221047'
  tag rid: 'SV-221047r622190_rule'
  tag stig_id: 'CISC-RT-000730'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-22751r408936_fix'
  tag 'documentable'
  tag legacy: ['SV-110915', 'V-101811']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
