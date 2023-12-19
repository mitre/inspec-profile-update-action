control 'SV-221140' do
  title 'The Cisco multicast Designated switch (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an IGMP or MLD membership report to the DR. In a Protocol Independent Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the group to the RP. Without any form of admission control, this can pose a security risk to the entire multicast domain, specifically the multicast switches along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP or MLD flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

Verify IGMP state limits have been configured on all applicable interfaces as shown in the example below:

interface Ethernet2/4
 no switchport
 ip address 10.2.22.3/24 
 ip pim sparse-mode
 ip igmp version 3
 ip igmp state-limit nnn

If the DR is not limiting multicast join requests via IGMP or MLD on all applicable interfaces, this is a finding.'
  desc 'fix', 'Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.

SW1(config)# int e2/4
SW1(config-if)# ip igmp state-limit 44 
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22855r409909_chk'
  tag severity: 'medium'
  tag gid: 'V-221140'
  tag rid: 'SV-221140r622190_rule'
  tag stig_id: 'CISC-RT-000880'
  tag gtitle: 'SRG-NET-000362-RTR-000122'
  tag fix_id: 'F-22844r409910_fix'
  tag 'documentable'
  tag legacy: ['SV-111173', 'V-102217']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
