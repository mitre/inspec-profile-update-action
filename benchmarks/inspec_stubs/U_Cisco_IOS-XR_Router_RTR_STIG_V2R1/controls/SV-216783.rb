control 'SV-216783' do
  title 'The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', "This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: verify that an inbound route policy has been configured for each customer neighbor as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.12.4.14
  remote-as 64514
    address-family ipv4 unicast
     route-policy FILTER _64514_ROUTES in
  !
 !
 neighbor x.12.4.16
  remote-as 64516
  address-family ipv4 unicast
   route-policy FILTER_64516_ROUTES in
 !

Step 2: Verify that the route policy permits only routes from each CE router with an originating AS that does not belong to that customer.

route-policy FILTER_64514_ROUTES
  if as-path originates-from 64514'  then
    pass
  else
    drop
  endif
end-policy
!
route-policy FILTER_64516_ROUTES
  if as-path originates-from 64516'  then
    pass
  else
    drop
  endif
end-policy

Note: The inbound route policy to filter customer prefixes can be nested with the above route policy as shown in the example below.

route-policy CUST1_INBOUND_FILTER
  apply CUST1_FILTER
  apply FILTER_64514_ROUTES
end-policy

If the router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding."
  desc 'fix', "This requirement is not applicable for the DODIN Backbone.

Configure the router to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Configure an inbound route policy for each customer to only accept routes with an originating AS that belongs to that customer as shown in the example below.

RP/0/0/CPU0:R2(config)#route-policy FILTER_64514_ROUTES
RP/0/0/CPU0:R2(config-rpl)#if as-path originates-from '64514' then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif 
RP/0/0/CPU0:R2(config-rpl)#end-policy 
RP/0/0/CPU0:R2(config)#route-policy FILTER_64516_ROUTES
RP/0/0/CPU0:R2(config-rpl)#if as-path originates-from '64516' then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif 
RP/0/0/CPU0:R2(config-rpl)#end-policy 

Step 2: Apply the appropriate inbound route policy with each peering CE router as shown in the example below.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.14
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy route-policy FILTER_64514_ROUTES in
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.16
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy FILTER_64516_ROUTES in
RP/0/0/CPU0:R2(config-bgp-nbr-af)#end"
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18015r288726_chk'
  tag severity: 'low'
  tag gid: 'V-216783'
  tag rid: 'SV-216783r531087_rule'
  tag stig_id: 'CISC-RT-000550'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-18013r288727_fix'
  tag 'documentable'
  tag legacy: ['SV-105911', 'V-96773']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
