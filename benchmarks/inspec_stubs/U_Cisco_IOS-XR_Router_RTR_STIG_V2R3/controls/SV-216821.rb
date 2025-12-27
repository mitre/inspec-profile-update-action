control 'SV-216821' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the router configuration to determine if there is export policy to block local source-active multicast advertisements.

Step 1: Verify that an outbound source-active filter is bound to each MSDP peer as shown in the example below.

router msdp
 sa-filter in list INBOUND_MSDP_SA_FILTER
 sa-filter out list OUTBOUND_MSDP_SA_FILTER

Step 2: Review the access lists referenced by the source-active filters and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local.

ipv4 access-list OUTBOUND_MSDP_SA_FILTER
 10 deny ipv4 10.0.0.0 0.255.255.255 any
 20 permit ipv4 any any

If the router is not configured with an export policy to filter local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the router with an export policy to avoid global visibility of local multicast (S, G) states. The example below will prevent exporting multicast active sources belonging to the private network.

RP/0/0/CPU0:R2(config)#ipv4 access-list OUTBOUND_MSDP_SA_FILTER
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 10.0.0.0 0.255.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip any any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#router msdp
RP/0/0/CPU0:R2(config-msdp)#sa-filter out list OUTBOUND_MSDP_SA_FILTER         
RP/0/0/CPU0:R2(config-msdp)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18053r288837_chk'
  tag severity: 'low'
  tag gid: 'V-216821'
  tag rid: 'SV-216821r531087_rule'
  tag stig_id: 'CISC-RT-000930'
  tag gtitle: 'SRG-NET-000018-RTR-000008'
  tag fix_id: 'F-18051r288838_fix'
  tag 'documentable'
  tag legacy: ['SV-105987', 'V-96849']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
