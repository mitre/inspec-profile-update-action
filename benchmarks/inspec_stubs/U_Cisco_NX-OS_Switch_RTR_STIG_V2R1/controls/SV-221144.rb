control 'SV-221144' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) switches to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, Martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the switch configuration to determine if there is import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Step 1: Verify that an inbound source-active filter is bound to each MSDP peer.

ip msdp peer x.1.28.2 connect-source Ethernet2/1 remote-as nn
ip msdp sa-policy x.1.28.2 prefix-list INBOUND_MSDP_SA_FILTER in

Step 2: Review the prefix-list or route-map referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

ip prefix-list INBOUND_MSDP_SA_FILTER seq 10 deny 224.0.1.3/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 15 deny 224.0.1.24/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 20 deny 224.0.1.22/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 25 deny 224.0.1.2/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 30 deny 224.0.1.35/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 35 deny 224.0.1.60/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 40 deny 224.0.1.39/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 45 deny 224.0.1.40/32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 50 deny 232.0.0.0/8 le 32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 55 deny 239.0.0.0/8 le 32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 60 deny 10.0.0.0/8 le 32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 70 deny 172.16.0.0/12 le 32 
ip prefix-list INBOUND_MSDP_SA_FILTER seq 75 permit 0.0.0.0/0 ge 8

If the switch is not configured with an import policy to filter undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP switch to filter received source-active multicast advertisements for any undesirable multicast groups and sources as shown in the example below:

SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 10 deny 224.0.1.3/32 
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 15 deny 224.0.1.24/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 20 deny 224.0.1.22/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 25 deny 224.0.1.2/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 30 deny 224.0.1.35/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 35 deny 224.0.1.60/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 40 deny 224.0.1.39/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 45 deny 224.0.1.40/32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 50 deny 232.0.0.0/8 le 32 
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 55 deny 239.0.0.0/8 le 32 
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 60 deny 10.0.0.0/8 le 32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 165 deny 127.0.0.0/8 le 32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 70 deny 172.16.0.0/12 le 32
SW1(config)# ip prefix-list INBOUND_MSDP_SA_FILTER seq 75 permit 0.0.0.0/0 ge 8
SW1(config)# exit
SW1(config)# ip msdp sa-policy x.1.28.2 prefix-list INBOUND_MSDP_SA_FILTER in
SW1(config)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22859r409921_chk'
  tag severity: 'low'
  tag gid: 'V-221144'
  tag rid: 'SV-221144r622190_rule'
  tag stig_id: 'CISC-RT-000920'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-22848r409922_fix'
  tag 'documentable'
  tag legacy: ['SV-111255', 'V-102299']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
