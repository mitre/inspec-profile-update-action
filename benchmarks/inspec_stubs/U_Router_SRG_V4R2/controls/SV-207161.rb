control 'SV-207161' do
  title 'The multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an IGMP or MLD membership report to the DR. In a Protocol Independent Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the group to the RP. Without any form of admission control, this can pose a security risk to the entire multicast domain - specifically the multicast routers along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP or MLD flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

If the DR is not limiting multicast join requests via IGMP or MLD, this is a finding.

Note: If both global and per-interface state limiters are configured, the limits configured for per-interface state limiters are still enforced but are constrained by the global limit.'
  desc 'fix', 'Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7422r382511_chk'
  tag severity: 'medium'
  tag gid: 'V-207161'
  tag rid: 'SV-207161r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000122'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7422r382512_fix'
  tag 'documentable'
  tag legacy: ['V-78335', 'SV-93041']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
