control 'SV-216777' do
  title 'The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for Bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.'
  desc 'check', 'Review the router configuration to verify that it will reject BGP routes for any Bogon prefixes.

Step 1: verify that an inbound route policy has been configured for each external neighbor as shown in the example below.

router bgp n
 address-family ipv4 unicast
 !
 neighbor x.1.23.3
  remote-as y
  keychain YYY_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
   route-policy BGP_FILTER in
  !
 !
 neighbor x.1.24.4
  remote-as z
  keychain ZZZ_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
   route-policy BGP_FILTER in
 !
!

Step 2: Review the route policy to determine if it is filtering at a minimum BOGON prefixes as shown in the example below.

route-policy BGP_FILTER
  if destination in BOGON_PREFIXES then
    drop
  else
    pass
  endif
end-policy 

Step 3: Review the prefix set referenced in the route policy above has been configured containing the current Bogon prefixes as shown in the example below.

prefix-set BOGON_PREFIXES
  0.0.0.0/8 le 32,
  10.0.0.0/8 le 32,
  100.64.0.0/10 le 32,
  127.0.0.0/8 le 32,
  169.254.0.0/16 le 32,
  172.16.0.0/12 le 32,
  192.0.2.0/24 le 32,
  192.88.99.0/24 le 32,
  192.168.0.0/16 le 32,
  198.18.0.0/15 le 32,
  198.51.100.0/24 le 32,
  203.0.113.0/24 le 32,
  240.0.0.0/4 le 32,
  224.0.0.0/4 le 32
end-set

If the router is not configured to reject inbound route advertisements for any Bogon prefixes, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements for any Bogon prefixes.

Step 1: Configure a prefix set containing the current Bogon prefixes as shown below.

RP/0/0/CPU0:R2(config)#prefix-set BOGON_PREFIXES   
RP/0/0/CPU0:R2(config-pfx)#0.0.0.0/8 le 32,
RP/0/0/CPU0:R2(config-pfx)#10.0.0.0/8 le 32,
RP/0/0/CPU0:R2(config-pfx)#100.64.0.0/10 le 32,
RP/0/0/CPU0:R2(config-pfx)#127.0.0.0/8 le 32,
RP/0/0/CPU0:R2(config-pfx)#169.254.0.0/16 le 32,
RP/0/0/CPU0:R2(config-pfx)#172.16.0.0/12 le 32,
RP/0/0/CPU0:R2(config-pfx)#192.0.2.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#192.88.99.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#192.168.0.0/16 le 32,
RP/0/0/CPU0:R2(config-pfx)#198.18.0.0/15 le 32,
RP/0/0/CPU0:R2(config-pfx)#198.51.100.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#203.0.113.0/24 le 32,
RP/0/0/CPU0:R2(config-pfx)#240.0.0.0/4 le 32,
RP/0/0/CPU0:R2(config-pfx)#224.0.0.0/4 le 32
RP/0/0/CPU0:R2(config-pfx)#end-set

Step 2: Configure the route policy to drop routes with BOGON prefixes as shown in the example below.

RP/0/0/CPU0:R2(config)#route-policy BGP_FILTER 
RP/0/0/CPU0:R2(config-rpl)#if destination in BOGON_PREFIXES then 
RP/0/0/CPU0:R2(config-rpl-if)#drop
RP/0/0/CPU0:R2(config-rpl-if)#else pass endif
RRP/0/0/CPU0:R2(config-rpl)#end-policy 
RP/0/0/CPU0:R2(config)#exit

Step 3: Apply the route policy to each external BGP neighbor as shown in the example.

RP/0/0/CPU0:R2(config)#router bgp xx
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER in
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.24.4
RP/0/0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-bgp-nbr-af)#route-policy BGP_FILTER in'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18009r288708_chk'
  tag severity: 'medium'
  tag gid: 'V-216777'
  tag rid: 'SV-216777r531087_rule'
  tag stig_id: 'CISC-RT-000490'
  tag gtitle: 'SRG-NET-000018-RTR-000002'
  tag fix_id: 'F-18007r288709_fix'
  tag 'documentable'
  tag legacy: ['SV-105899', 'V-96761']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
