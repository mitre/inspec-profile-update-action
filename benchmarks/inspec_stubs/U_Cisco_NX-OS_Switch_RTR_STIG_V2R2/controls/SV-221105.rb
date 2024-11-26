control 'SV-221105' do
  title 'The Cisco BGP switch must be configured to reject inbound route advertisements from a customer edge (CE) switch for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking switches connected to the Internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the switch configuration to verify that there are ACLs defined to only accept routes for prefixes that belong to specific customers. 

Step 1: Verify prefix list has been configured for each customer containing prefixes belonging to each customer as shown in the example below:

ip prefix-list PREFIX_FILTER_CUST1 seq 5 permit x.13.1.0/24 le 32
ip prefix-list PREFIX_FILTER_CUST1 seq 10 deny 0.0.0.0/0 ge 8
ip prefix-list PREFIX_FILTER_CUST2 seq 5 permit x.13.2.0/24 le 32
ip prefix-list PREFIX_FILTER_CUST2 seq 10 deny 0.0.0.0/0 ge 8

Step 2: Verify that the prefix lists has been applied to all to the applicable CE peers as shown in the example below:

router bgp xx
 router-id 10.1.1.1
 neighbor x.55.14.2 remote-as 64514
 password 3 7b07d1b3023056a9
 address-family ipv4 unicast
 prefix-list FILTER_PREFIXES_CUST1 in
 neighbor x.55.14.4 remote-as 64516
 password 3 f07a10cb41db8bb6f8f0a340049a9b02
 address-family ipv4 unicast
 prefix-list FILTER_PREFIXES_CUST1 in

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.

If the switch is not configured to reject inbound route advertisements from each CE switch for prefixes that are not allocated to that customer, this is a finding.'
  desc 'fix', 'Configure the switch to reject inbound route advertisements from each CE switch for prefixes that are not allocated to that customer.

Step 1: Configure a prefix list for each customer containing prefixes belonging to each.

SW1(config)# ip prefix-list PREFIX_FILTER_CUST1 permit x.13.1.0/24 le 32
SW1(config)# ip prefix-list PREFIX_FILTER_CUST1 deny 0.0.0.0/0 ge 8
SW1(config)# ip prefix-list PREFIX_FILTER_CUST2 permit x.13.2.0/24 le 32
SW1(config)# ip prefix-list PREFIX_FILTER_CUST2 deny 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter inbound to each CE neighbor as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.55.14.2
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# prefix-list PREFIX_FILTER_CUST1 in
SW1(config-router-neighbor-af)# exit
SW1(config-router-neighbor)# exit
SW1(config-router)# neighbor x.55.14.4
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# prefix-list PREFIX_FILTER_CUST2 in
SW1(config-router-neighbor-af)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22820r409804_chk'
  tag severity: 'medium'
  tag gid: 'V-221105'
  tag rid: 'SV-221105r622190_rule'
  tag stig_id: 'CISC-RT-000510'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-22809r409805_fix'
  tag 'documentable'
  tag legacy: ['SV-111029', 'V-101925']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
