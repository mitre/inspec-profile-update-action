control 'SV-216820' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. 

MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. 

When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. 

Configuring an import policy to block multicast advertisements for reserved, Martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the router configuration to determine if there is import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

router msdp
 sa-filter in list INBOUND_MSDP_SA_FILTER

Step 2: Review the access lists referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

ipv4 access-list INBOUND_MSDP_SA_FILTER
 10 deny ipv4 any host 224.0.1.3
 20 deny ipv4 any host 224.0.1.24
 30 deny ipv4 any host 224.0.1.22
 40 deny ipv4 any host 224.0.1.2
 50 deny ipv4 any host 224.0.1.35
 60 deny ipv4 any host 224.0.1.60
 70 deny ipv4 any host 224.0.1.39
 80 deny ipv4 any host 224.0.1.40
 90 deny ipv4 any 232.0.0.0 0.255.255.255
 100 deny ipv4 any 239.0.0.0 0.255.255.255
 110 deny ipv4 10.0.0.0 0.255.255.255 any
 120 deny ipv4 127.0.0.0 0.255.255.255 any
 130 deny ipv4 172.16.0.0 0.15.255.255 any
 140 deny ipv4 192.168.0.0 0.0.255.255 any
 150 permit ipv4 any any

If the router is not configured with an import policy to filter undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP router to filter received source-active multicast advertisements for any undesirable multicast groups and sources as shown in the example below.

RP/0/0/CPU0:R2(config)#ipv4 access-list INBOUND_MSDP_SA_FILTER
RP/0/0/CPU0:R2(config-ipv4-acl)#deny   ip any host 224.0.1.3
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.24
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.22
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.2
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.35
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.60
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.39
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any host 224.0.1.40
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any 232.0.0.0 0.255.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any 239.0.0.0 0.255.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 10.0.0.0 0.255.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 127.0.0.0 0.255.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 172.16.0.0 0.15.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 192.168.0.0 0.0.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 any any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#router msdp
RP/0/0/CPU0:R2(config-msdp)#sa-filter in list INBOUND_MSDP_SA_FILTER
RP/0/0/CPU0:R2(config-msdp)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18052r288834_chk'
  tag severity: 'low'
  tag gid: 'V-216820'
  tag rid: 'SV-216820r531087_rule'
  tag stig_id: 'CISC-RT-000920'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-18050r288835_fix'
  tag 'documentable'
  tag legacy: ['SV-105985', 'V-96847']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
