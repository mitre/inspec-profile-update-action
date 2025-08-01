control 'SV-216785' do
  title 'The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if it is compliant with this requirement.

Step 1: Verify that an inbound route policy has been configured for each CE router as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.12.4.14
  remote-as 64514
    address-family ipv4 unicast
     route-policy FILTER_LONG_PREFIXES in
  !
 !
 neighbor x.12.4.16
  remote-as 64516
  address-family ipv4 unicast
   route-policy FILTER_LONG_PREFIXES in
 !

Step 2: Verify that the route policy permits only routes from each CE router with a prefix  length of 24 or shorter or the least significant prefixes issued to the customer as shown in the example below.

route-policy FILTER_LONG_PREFIXES
  if destination in PREFIX_LENGTH then
    pass
  else
    drop
  endif
end-policy

Note: The inbound route policy to filter customer prefixes can be nested with the above route policy as shown in the example below.

route-policy CUST1_INBOUND_FILTER
  apply CUST1_FILTER
  apply FILTER_64514_ROUTES
  apply FILTER_LONG_PREFIXES
end-policy

Step 3: Review the prefix set referenced in the route policy above to determine if it only allows a prefix length 24 or shorter.

prefix-set PREFIX_LENGTH
 0.0.0.0/0 ge 8 le 24
end-set

If the router is not configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.

Step 1: Configure a prefix set to not include prefixes are longer than /24.

RP/0/0/CPU0:R2(config)#prefix-set PREFIX_LENGTH
RP/0/0/CPU0:R2(config-pfx)#0.0.0.0/0 ge 8 le 24
RP/0/0/CPU0:R2(config-pfx)#end-set

Step 2: Configure a route policy to only accept prefixes that are /24 or shorter as shown in the example below.

RP/0/0/CPU0:R2(config)#route-policy FILTER_LONG_PREFIXES
RP/0/0/CPU0:R2(config-rpl)#if destination in PREFIX_LENGTH then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif 
RP/0/0/CPU0:R2(config-rpl)#end-policy

Step 3: Apply the route policy above inbound with each peering CE router as shown in the example below.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.14
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy route-policy FILTER_LONG_PREFIXES in
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.16
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy FILTER_LONG_PREFIXES in
RP/0/0/CPU0:R2(config-bgp-nbr-af)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18017r288732_chk'
  tag severity: 'low'
  tag gid: 'V-216785'
  tag rid: 'SV-216785r856446_rule'
  tag stig_id: 'CISC-RT-000570'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-18015r288733_fix'
  tag 'documentable'
  tag legacy: ['SV-105915', 'V-96777']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
