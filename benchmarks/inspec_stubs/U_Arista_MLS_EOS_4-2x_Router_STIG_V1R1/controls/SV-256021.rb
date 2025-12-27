control 'SV-256021' do
  title 'The Arista router must be configured to block any traffic that is destined to IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as Layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all routers at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Review the Arista router configuration to verify an ingress ACL is applied to all CE-facing interfaces. 

Verify the ingress ACL rejects and logs packets destined to the IP core address block. 

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent peers.

Step 1: Verify the ingress ACL is configured to drop any traffic with destination address assigned to the IP core infrastructure. Execute the command "sh ip access-list".

ip access-list DROP_INBOUND
deny ip any 172.16.0.0/16 log 
permit icmp any any 
permit ip any any 

Step 2: To verify the ingress ACL applied to all CE facing interfaces inbound to drop all the traffic coming toward the CE, execute the command "sh run int Eth YY".

interface Ethernet 2
ip access-group DROP_INBOUND in

If the Arista PE router is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Step 1: Configure an ingress ACL to drop any traffic with destination address assigned to the IP core infrastructure.

router(config)#ip access-list DROP_INBOUND
router(config-acl-DROP_INBOUND)#deny ip any 172.16.0.0/16 log 
router(config-acl-DROP_INBOUND)#permit icmp any any 
router(config-acl-DROP_INBOUND)#permit ip any any 
router(config-acl-DROP_INBOUND)#exit

Step 2: Apply the ACL to all CE-facing interfaces inbound to drop all the traffic coming toward the CE.

router(config)#interface Ethernet 2
router(config-if-Et2)#ip access-group DROP_INBOUND in
router(config-if-Et2)#end'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59697r882403_chk'
  tag severity: 'high'
  tag gid: 'V-256021'
  tag rid: 'SV-256021r882405_rule'
  tag stig_id: 'ARST-RT-000400'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-59640r882404_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
