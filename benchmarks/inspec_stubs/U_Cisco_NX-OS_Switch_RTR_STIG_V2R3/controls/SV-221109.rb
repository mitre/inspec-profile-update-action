control 'SV-221109' do
  title 'The Cisco BGP switch must be configured to reject route advertisements from CE switches with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE switches must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', 'Review the switch configuration to verify the switch is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

Step 1: Review switch configuration and verify that there is an as-path access-list statement defined to only accept routes from a CE switch whose AS did not originate the route. The configuration should look similar to the following:

ip as-path access-list AS_PATH permit ^yy$
ip as-path access-list 10 AS_PATH .*

Note: the characters “^” and “$” representing the beginning and the end of the expression respectively are optional and are implicitly defined if omitted.

Step 2: Verify that the as-path access-list is referenced by the filter-list inbound for the appropriate BGP neighbors as shown in the example below:

router bgp xx
 router-id 10.1.1.1
 neighbor x.1.12.2 remote-as xx
 password 3 7b07d1b3023056a9
 address-family ipv4 unicast
 filter-list AS_PATH in

If the switch is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure the switch to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

Step 1: Configure the as-path ACL as shown in the example below:

SW1(config)# ip as-path access-list AS_PATH permit ^22$
SW1(config)# ip as-path access-list AS_PATH deny .*

Step 2: Apply the as-path filter inbound as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.1.12.2
SW1(config-router-neighbor)# address-family ipv4 unicast 
SW1(config-router-neighbor-af)# filter-list AS_PATH in
SW1(config-router-neighbor-af)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22824r409816_chk'
  tag severity: 'low'
  tag gid: 'V-221109'
  tag rid: 'SV-221109r622190_rule'
  tag stig_id: 'CISC-RT-000550'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-22813r409817_fix'
  tag 'documentable'
  tag legacy: ['SV-111037', 'V-101933']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
