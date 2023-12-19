control 'SV-216780' do
  title 'The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an autonomous system for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute IGP routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: verify that an outbound route policy has been configured for each customer neighbor as shown in the example below.

router bgp xx
 address-family ipv4 unicast
 !
 neighbor x.12.4.14
  remote-as 64514
    address-family ipv4 unicast
     route-policy CE_ADVERTISEMENTS out
  !
 !
 neighbor x.12.4.16
  remote-as 64516
  address-family ipv4 unicast
   route-policy CE_ADVERTISEMENTS out
 !
!

Step 2: Review the route policy to determine if it is accepting only prefixes belonging to customers or the local autonomous system as shown in the example below.

route-policy CE_ADVERTISEMENTS
  if destination in CE_PREFIX_ADVERTISEMENTS then
    pass
  else
    drop
  endif
end-policy

Step 3: Review the prefix sets referenced in the route policy above to determine if they include only prefixes belonging to customers or the local autonomous system as shown in the example below.

prefix-set CE_PREFIX_ADVERTISEMENTS
  x.13.1.0/24 le 32,
  x.13.2.0/24 le 32,
  x.13.3.0/24 le 32,
  x.13.4.0/24 le 32
end-set

If the router is not configured to reject outbound route advertisements that do not belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Configure a prefix set for customer and local autonomous system prefixes as shown in the example.

RP/0/0/CPU0:R2(config)#prefix-set CE_PREFIX_ADVERTISEMENTS
RP/0/0/CPU0:R2(config-pfx)#x.13.1.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#x.13.2.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#x.13.3.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#x.13.4.0/24 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set

Step 2: Configure a route policy filter for allow customer and local autonomous system prefixes as shown in the example.

RP/0/0/CPU0:R2(config)#route-policy CE_ADVERTISEMENTS
RP/0/0/CPU0:R2(config-rpl)#if destination in CE_PREFIX_ADVERTISEMENTS then
RP/0/0/CPU0:R2(config-rpl-if)#pass
RP/0/0/CPU0:R2(config-rpl-if)#else
RP/0/0/CPU0:R2(config-rpl-else)#drop
RP/0/0/CPU0:R2(config-rpl-else)#endif
RP/0/0/CPU0:R2(config-rpl)#end-policy

Step 3: Apply the route policy to each customer neighbor as shown in the example.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.14
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy route-policy CE_ADVERTISEMENTS out 
RP/0/0/CPU0:R2(config-bgp)#neighbor x.12.4.16
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy CE_ADVERTISEMENTS out
RP/0/0/CPU0:R2(config-bgp-nbr-af)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18012r288717_chk'
  tag severity: 'medium'
  tag gid: 'V-216780'
  tag rid: 'SV-216780r531087_rule'
  tag stig_id: 'CISC-RT-000520'
  tag gtitle: 'SRG-NET-000018-RTR-000005'
  tag fix_id: 'F-18010r288718_fix'
  tag 'documentable'
  tag legacy: ['SV-105905', 'V-96767']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
