control 'SV-216779' do
  title 'The Cisco BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the Internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the router configuration to verify that there are ACLs defined to only accept routes for prefixes that belong to specific customers. 

Step 1: Verify that an inbound route policy has been configured for each customer neighbor as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.12.4.14
  remote-as 64514
    address-family ipv4 unicast
   route-policy CUST1_PREFIX_FILTER in
  !
 !
 neighbor x.12.4.16
  remote-as 64516
  address-family ipv4 unicast
   route-policy CUST2_PREFIX_FILTER in
 !
!

Step 2: Review the route policies to determine if it is accepting only prefixes belonging to each customer as shown in the example below.

route-policy CUST1_PREFIX_FILTER
  if destination in CUST1_PREFIX then
    pass
  else
    drop
  endif
end-policy
!
route-policy CUST2_PREFIX_FILTER
  if destination in CUST2_PREFIX then
    pass
  else
    drop
  endif
end-policy

Step 3: Review the prefix sets referenced in the route policies above to determine if they include only prefixes belonging to each customer.

prefix-set CUST1_PREFIX
  x.1.1.0/24 le 32
end-set
!
prefix-set CUST2_PREFIX
  x.2.1.0/24 le 32
end-set

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.

If the router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer.

Step 1: Configure a prefix set for each customer containing prefixes belonging to each as shown in the example.

RP/0/0/CPU0:R2(config)#prefix-set CUST1_PREFIX
RP/0/0/CPU0:R2(config-pfx)#x.1.1.0/24 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set
RP/0/0/CPU0:R2(config)#prefix-set CUST2_PREFIX
RP/0/0/CPU0:R2(config-pfx)#x.2.1.0/24 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set 

Step 2: Configure a route policy filter for each customer as shown in the example.

RP/0/0/CPU0:R2(config)#route-policy CUST1_PREFIX_FILTER          
RP/0/0/CPU0:R2(config-rpl)#if destination in CUST1_PREFIX then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif
RP/0/0/CPU0:R2(config-rpl)#end-policy
RP/0/0/CPU0:R2(config)#route-policy CUST2_PREFIX_FILTER          
RP/0/0/CPU0:R2(config-rpl)#if destination in CUST2_PREFIX then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif
RP/0/0/CPU0:R2(config-rpl)#end-policy

Step 3: Apply the route policy to each customer neighbor as shown in the example.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.14
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy CUST1_PREFIX_FILTER in
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.16
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy CUST2_PREFIX_FILTER in'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18011r288714_chk'
  tag severity: 'medium'
  tag gid: 'V-216779'
  tag rid: 'SV-216779r531087_rule'
  tag stig_id: 'CISC-RT-000510'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-18009r288715_fix'
  tag 'documentable'
  tag legacy: ['SV-105903', 'V-96765']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
