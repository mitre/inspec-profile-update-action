control 'SV-255994' do
  title 'The Arista Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the Arista router configuration to determine if there is export policy to block local source-active multicast advertisements.

Step 1: Verify that an outbound source-active filter is bound to each MSDP peer.

To verify the MSDP peer is configured and to verify the source-active filter is configured outbound, execute the command "show ip msdp peer X.1.12.2 and show ip msdp summary".

router msdp 
 peer 10.1.12.2
  sa-filter out PIM_NEIGHBOR_SA_FILTER

Step 2: Review the access lists referenced by the source-active filters and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local.

To verify IP access lists are configured, execute the command "show ip access-lists".

ip access-list PIM_NEIGHBOR_SA_FILTER
   10 deny ip any 224.1.1.0/24
   20 deny ip any 224.1.2.0/24
   30 deny ip any 224.1.3.0/24
   40 deny ip any 224.1.4.0/24
   100 permit ip any any

If the router is not configured with an export policy to block local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Step 1: Configure Arista router to ensure an export policy is implemented on all MSDP routers to avoid global visibility of local multicast (S,G) states.

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
  tag check_id: 'C-59670r882322_chk'
  tag severity: 'low'
  tag gid: 'V-255994'
  tag rid: 'SV-255994r882324_rule'
  tag stig_id: 'ARST-RT-000080'
  tag gtitle: 'SRG-NET-000018-RTR-000008'
  tag fix_id: 'F-59613r882323_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
