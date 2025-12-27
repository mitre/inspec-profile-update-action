control 'SV-207103' do
  title 'The Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the router configuration to determine if there is an import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

Step 2: Review the access lists referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

If the router is not configured with an import policy to block undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP router to implement an import policy to block multicast advertisements for undesirable multicast groups and sources.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7364r382154_chk'
  tag severity: 'low'
  tag gid: 'V-207103'
  tag rid: 'SV-207103r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000007'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7364r382155_fix'
  tag 'documentable'
  tag legacy: ['V-78343', 'SV-93049']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
