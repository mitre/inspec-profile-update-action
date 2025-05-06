control 'SV-216778' do
  title 'The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc 'check', 'Review the router configuration to verify that it will reject routes belonging to the local AS.

Step 1: verify that an inbound route policy has been configured for each external neighbor as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.1.23.3
  remote-as yy
  keychain YYY_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
   route-policy BGP_FILTER_INBOUND in
  !
 !
 neighbor x.1.24.4
  remote-as zz
  keychain ZZZ_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
   route-policy BGP_FILTER_INBOUND in
 !
!

Step 2: Review the route policy to determine if it is filtering at a minimum local prefixes as shown in the example below.

route-policy BGP_FILTER_INBOUND
  if destination in LOCAL_PREFIX then
    drop
  else
    pass
  endif
end-policy 

Note: If bogons are also filtered per previous requirement, the route policy would look similar to the following example:

route-policy BGP_FILTER_INBOUND
  if destination in BOGON_PREFIXES then
    drop
  elseif destination in LOCAL_PREFIX then
    drop
  else
    pass
  endif
end-policy

Step 3: Review the prefix set referenced in the route policy above to determine if it includes the local global prefix as shown in the example below.

prefix-set LOCAL_PREFIX
 x.13.1.0/24 le 32
end-set

If the router is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Step 1: Configure a prefix set containing the current Bogon prefixes as shown below.

RP/0/0/CPU0:R2(config)#prefix-set Step 1: Configure a prefix set containing the current Bogon prefixes as shown below.

RP/0/0/CPU0:R2(config)#prefix-set LOCAL_PREFIX
RP/0/0/CPU0:R2(config-pfx)#x.13.1.0/24 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set

Step 2: Configure the route policy to drop routes with BOGON prefixes as shown in the example below.

RP/0/0/CPU0:R2(config)#route-policy BGP_FILTER_INBOUND
RP/0/0/CPU0:R2(config-rpl)#if destination in LOCAL_PREFIX then 
RP/0/0/CPU0:R2(config-rpl-if)#drop
RP/0/0/CPU0:R2(config-rpl-if)#else pass endif
RRP/0/0/CPU0:R2(config-rpl)#end-policy 
RP/0/0/CPU0:R2(config)#exit

Step 3: Apply the route policy to each external BGP neighbor as shown in the example.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER_INBOUND in
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.24.4
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER_INBOUND in'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18010r288711_chk'
  tag severity: 'medium'
  tag gid: 'V-216778'
  tag rid: 'SV-216778r531087_rule'
  tag stig_id: 'CISC-RT-000500'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-18008r288712_fix'
  tag 'documentable'
  tag legacy: ['V-96763', 'SV-105901']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
