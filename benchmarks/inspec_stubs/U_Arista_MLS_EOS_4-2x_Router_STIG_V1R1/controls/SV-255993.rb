control 'SV-255993' do
  title 'The Arista Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the Arista router configuration to determine if there is an import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

To verify the MSDP peer is configured and the source-active filter is configured inbound, execute the command "show run | sec router msdp".

router msdp 
 peer 10.1.12.2
  sa-filter in PIM_NEIGHBOR_SA_FILTER

Step 2: Review the access lists referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

To verify IP access lists are configured, execute the command "show ip access-lists".

ip access-list PIM_NEIGHBOR_SA_FILTER
   10 deny ip any 224.1.1.0/24
   20 deny ip any 224.1.2.0/24
   30 deny ip any 224.1.3.0/24
   40 deny ip any 224.1.4.0/24
   100 permit ip any any

If the router is not configured with an import policy to block undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Step 1: Configure the Arista router to implement policy to filter multicast advertisements for undesirable multicast groups and sources.

router msdp 
 peer 10.1.12.2
  sa-filter in PIM_NEIGHBOR_SA_FILTER

Step 2: Configure the source active access-list.

ip access-list PIM_NEIGHBOR_SA_FILTER
   10 deny ip any 224.1.1.0/24
   20 deny ip any 224.1.2.0/24
   30 deny ip any 224.1.3.0/24
   40 deny ip any 224.1.4.0/24
   100 permit ip any any'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59669r882319_chk'
  tag severity: 'low'
  tag gid: 'V-255993'
  tag rid: 'SV-255993r882321_rule'
  tag stig_id: 'ARST-RT-000070'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-59612r882320_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
