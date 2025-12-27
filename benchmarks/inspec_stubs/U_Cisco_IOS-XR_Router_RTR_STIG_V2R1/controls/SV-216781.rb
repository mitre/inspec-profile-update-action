control 'SV-216781' do
  title 'The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Step 1: verify that an outbound route policy has been configured for each external neighbor as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.1.23.3
  remote-as yy
  address-family ipv4 unicast
   route-policy BGP_FILTER_OUTBOUND out
  !
 !
 neighbor x.1.24.4
  remote-as zz
  address-family ipv4 unicast
   route-policy BGP_FILTER_OUTBOUND out
 !
!

Step 2: Review the route policy to determine if it is filtering at a minimum IP core prefixes as shown in the example below.

route-policy BGP_FILTER_OUTBOUND
  if destination in CORE_PREFIX then
    drop
  else
    pass
  endif
end-policy 

Step 3: Review the prefix set referenced in the route policy above to determine if it includes the IP core prefix as shown in the example below.

prefix-set CORE_PREFIX
 10.1.1.0/24 le 32
end-set

If the router is not configured to reject outbound route advertisements for prefixes belonging to the IP core, this is a finding.'
  desc 'fix', 'Step 1: Configure a prefix set containing the IP core prefix as shown below.

RP/0/0/CPU0:R2(config)#prefix-set 

Step 2: Configure a prefix set containing the current Bogon prefixes as shown below.

RP/0/0/CPU0:R2(config)#prefix-set CORE_PREFIX
RP/0/0/CPU0:R2(config-pfx)#10.1.1.0/24 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set

Step 3: Configure the route policy to drop route advertisements for IP core prefixes as shown in the example below.

RP/0/0/CPU0:R2(config)#route-policy BGP_FILTER_OUTBOUND
RP/0/0/CPU0:R2(config-rpl)#if destination in CORE_PREFIX then
RP/0/0/CPU0:R2(config-rpl-if)#drop
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#pass
RP/0/0/CPU0:R2(config-rpl-else)#endif
RP/0/0/CPU0:R2(config-rpl)#end-policy

Step 4: Apply the route policy to each external BGP neighbor as shown in the example.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER_OUTBOUND out
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.24.4
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER_ OUTBOUND out'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18013r288720_chk'
  tag severity: 'medium'
  tag gid: 'V-216781'
  tag rid: 'SV-216781r531087_rule'
  tag stig_id: 'CISC-RT-000530'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-18011r288721_fix'
  tag 'documentable'
  tag legacy: ['V-96769', 'SV-105907']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
