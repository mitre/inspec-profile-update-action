control 'SV-216635' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, Martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the router configuration to determine if there is import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

ip msdp peer x.1.28.2 remote-as 2
ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER

Step 2: Review the access lists referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

ip access-list extended INBOUND_MSDP_SA_FILTER
 deny   ip any host 224.0.1.3
 deny   ip any host 224.0.1.24
 deny   ip any host 224.0.1.22
 deny   ip any host 224.0.1.2
 deny   ip any host 224.0.1.35
 deny   ip any host 224.0.1.60
 deny   ip any host 224.0.1.39
 deny   ip any host 224.0.1.40
 deny   ip any 232.0.0.0 0.255.255.255
 deny   ip any 239.0.0.0 0.255.255.255
 deny   ip 10.0.0.0 0.255.255.255 any
 deny   ip 127.0.0.0 0.255.255.255 any
 deny   ip 172.16.0.0 0.15.255.255 any
 deny   ip 192.168.0.0 0.0.255.255 any
 permit ip any any

If the router is not configured with an import policy to filter undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP router to filter received source-active multicast advertisements for any undesirable multicast groups and sources as shown in the example below.

R8(config)#ip access-list extended INBOUND_MSDP_SA_FILTER
R8(config-ext-nacl)#deny ip any host 224.0.1.3                       ! Rwhod 
R8(config-ext-nacl)#deny ip any host 224.0.1.24                     ! Microsoft-ds
R8(config-ext-nacl)#deny ip any host 224.0.1.22                     ! SVRLOC
R8(config-ext-nacl)#deny ip any host 224.0.1.2                       ! SGI-Dogfight
R8(config-ext-nacl)#deny ip any host 224.0.1.35                    ! SVRLOC-DA
R8(config-ext-nacl)#deny ip any host 224.0.1.60                    ! hp-device-disc
R8(config-ext-nacl)#deny ip any host 224.0.1.39                     ! Auto-RP
R8(config-ext-nacl)#deny ip any host 224.0.1.40                     ! Auto-RP
R8(config-ext-nacl)#deny ip any 232.0.0.0 0.255.255.255     ! SSM range
R8(config-ext-nacl)#deny ip any 239.0.0.0 0.255.255.255     ! Admin scoped range
R8(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any       ! RFC 1918 address range
R8(config-ext-nacl)#deny ip 127.0.0.0 0.255.255.255 any     ! RFC 1918 address range
R8(config-ext-nacl)#deny ip 172.16.0.0 0.15.255.255 any     ! RFC 1918 address range
R8(config-ext-nacl)#deny ip 192.168.0.0 0.0.255.255 any   ! RFC 1918 address range
R8(config-ext-nacl)#permit ip any any
R8(config-ext-nacl)#exit
R8(config)#ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17870r287274_chk'
  tag severity: 'low'
  tag gid: 'V-216635'
  tag rid: 'SV-216635r531085_rule'
  tag stig_id: 'CISC-RT-000920'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-17866r287275_fix'
  tag 'documentable'
  tag legacy: ['V-96669', 'SV-105807']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
