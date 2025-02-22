control 'SV-216599' do
  title 'The Cisco BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the Internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the router configuration to verify that there are ACLs defined to only accept routes for prefixes that belong to specific customers.

Step 1: Verify prefix list has been configured for each customer containing prefixes belonging to each customer as shown in the example below.

ip prefix-list PREFIX_FILTER_CUST1 seq 5 permit x.13.1.0/24 le 32
ip prefix-list PREFIX_FILTER_CUST1 seq 10 deny 0.0.0.0/0 ge 8
ip prefix-list PREFIX_FILTER_CUST2 seq 5 permit x.13.2.0/24 le 32
ip prefix-list PREFIX_FILTER_CUST2 seq 10 deny 0.0.0.0/0 ge 8

Step 2: Verify that the prefix lists has been applied to all to the applicable CE peers as shown in the example below.

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.12.4.14 remote-as 64514
 neighbor x.12.4.14 prefix-list FILTER_PREFIXES_CUST1 in
 neighbor x.12.4.16 remote-as 64516
 neighbor x.12.4.16 prefix-list FILTER_PREFIXES_CUST2 in

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.

NOTE: This check is NA for JRSS systems.

If the router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer.

Step 1: Configure a prefix list for each customer containing prefixes belonging to each.

R1(config)#ip prefix-list PREFIX_FILTER_CUST1 permit x.13.1.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER_CUST1 deny 0.0.0.0/0 ge 8
R1(config)#ip prefix-list PREFIX_FILTER_CUST2 permit x.13.2.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER_CUST2 deny 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter inbound to each CE neighbor as shown in the example.

R1(config)#router bgp xx
R1(config-router)#neighbor x.12.4.14 prefix-list FILTER_PREFIXES_CUST1 in
R1(config-router)#neighbor x.12.4.16 prefix-list FILTER_PREFIXES_CUST2 in'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17834r917411_chk'
  tag severity: 'medium'
  tag gid: 'V-216599'
  tag rid: 'SV-216599r917412_rule'
  tag stig_id: 'CISC-RT-000510'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-17830r287170_fix'
  tag 'documentable'
  tag legacy: ['SV-105737', 'V-96599']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
