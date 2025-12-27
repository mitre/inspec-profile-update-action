control 'SV-216636' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the router configuration to determine if there is export policy to block local source-active multicast advertisements.

Step 1: Verify that an outbound source-active filter is bound to each MSDP peer as shown in the example below.

ip msdp peer 10.1.28.8 remote-as 8
ip msdp sa-filter out 10.1.28.8 list OUTBOUND_MSDP_SA_FILTER

Step 2: Review the access lists referenced by the source-active filters and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local.

ip access-list extended OUTBOUND_MSDP_SA_FILTER
 deny   ip 10.0.0.0 0.255.255.255 any
 permit ip any any

If the router is not configured with an export policy to filter local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the router with an export policy avoid global visibility of local multicast (S, G) states. The example below will prevent exporting multicast active sources belonging to the private network.

R8(config)#ip access-list extended OUTBOUND_MSDP_SA_FILTER
R8(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any
R8(config-ext-nacl)#permit ip any any
R8(config-ext-nacl)#exit
R8(config)#ip msdp sa-filter in x.1.28.2 list OUTBOUND_MSDP_SA_FILTER'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17871r287277_chk'
  tag severity: 'low'
  tag gid: 'V-216636'
  tag rid: 'SV-216636r531085_rule'
  tag stig_id: 'CISC-RT-000930'
  tag gtitle: 'SRG-NET-000018-RTR-000008'
  tag fix_id: 'F-17867r287278_fix'
  tag 'documentable'
  tag legacy: ['V-96671', 'SV-105809']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
