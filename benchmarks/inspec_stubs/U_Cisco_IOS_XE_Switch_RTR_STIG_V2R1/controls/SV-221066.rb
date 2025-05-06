control 'SV-221066' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) switches to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, Martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the switch configuration to determine if there is import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

ip msdp peer x.1.28.2 remote-as 2
ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER

Step 2: Review the access lists referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

ip access-list extended INBOUND_MSDP_SA_FILTER
 deny ip any host 224.0.1.3
 deny ip any host 224.0.1.24
 deny ip any host 224.0.1.22
 deny ip any host 224.0.1.2
 deny ip any host 224.0.1.35
 deny ip any host 224.0.1.60
 deny ip any host 224.0.1.39
 deny ip any host 224.0.1.40
 deny ip any 232.0.0.0 0.255.255.255
 deny ip any 239.0.0.0 0.255.255.255
 deny ip 10.0.0.0 0.255.255.255 any
 deny ip 127.0.0.0 0.255.255.255 any
 deny ip 172.16.0.0 0.15.255.255 any
 deny ip 192.168.0.0 0.0.255.255 any
 permit ip any any

If the switch is not configured with an import policy to filter undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP switch to filter received source-active multicast advertisements for any undesirable multicast groups and sources as shown in the example below:

SW1(config)#ip access-list extended INBOUND_MSDP_SA_FILTER
SW1(config-ext-nacl)#deny ip any host 224.0.1.3 ! Rwhod 
SW1(config-ext-nacl)#deny ip any host 224.0.1.24 ! Microsoft-ds
SW1(config-ext-nacl)#deny ip any host 224.0.1.22 ! SVRLOC
SW1(config-ext-nacl)#deny ip any host 224.0.1.2 ! SGI-Dogfight
SW1(config-ext-nacl)#deny ip any host 224.0.1.35 ! SVRLOC-DA
SW1(config-ext-nacl)#deny ip any host 224.0.1.60 ! hp-device-disc
SW1(config-ext-nacl)#deny ip any host 224.0.1.39 ! Auto-RP
SW1(config-ext-nacl)#deny ip any host 224.0.1.40 ! Auto-RP
SW1(config-ext-nacl)#deny ip any 232.0.0.0 0.255.255.255 ! SSM range
SW1(config-ext-nacl)#deny ip any 239.0.0.0 0.255.255.255 ! Admin scoped range
SW1(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any ! RFC 1918 address range
SW1(config-ext-nacl)#deny ip 127.0.0.0 0.255.255.255 any ! RFC 1918 address range
SW1(config-ext-nacl)#deny ip 172.16.0.0 0.15.255.255 any ! RFC 1918 address range
SW1(config-ext-nacl)#deny ip 192.168.0.0 0.0.255.255 any ! RFC 1918 address range
SW1(config-ext-nacl)#permit ip any any
SW1(config-ext-nacl)#exit
SW1(config)#ip msdp sa-filter in x.1.28.2 list INBOUND_MSDP_SA_FILTER'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22781r408992_chk'
  tag severity: 'low'
  tag gid: 'V-221066'
  tag rid: 'SV-221066r622190_rule'
  tag stig_id: 'CISC-RT-000920'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-22770r408993_fix'
  tag 'documentable'
  tag legacy: ['SV-110953', 'V-101849']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
