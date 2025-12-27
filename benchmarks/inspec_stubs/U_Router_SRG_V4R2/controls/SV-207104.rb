control 'SV-207104' do
  title 'The Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the router configuration to determine if there is export policy to block local source-active multicast advertisements.

Verify that an outbound source-active filter is bound to each MSDP peer.

Review the access lists referenced by the source-active filters and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local.

If the router is not configured with an export policy to block local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Ensure an export policy is implemented on all MSDP routers to avoid global visibility of local multicast (S, G) states.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7365r382157_chk'
  tag severity: 'low'
  tag gid: 'V-207104'
  tag rid: 'SV-207104r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000008'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7365r382158_fix'
  tag 'documentable'
  tag legacy: ['V-78345', 'SV-93051']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
