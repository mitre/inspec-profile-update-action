control 'SV-216631' do
  title 'The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an IGMP or MLD membership report to the DR. In a Protocol Independent Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the group to the RP. Without any form of admission control, this can pose a security risk to the entire multicast domain - specifically the multicast routers along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP or MLD flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command as shown in the example.

interface GigabitEthernet0/0
 ip address 10.3.3.3 255.255.255.0
 …
 …
 …
 ip igmp limit nn

If the DR is not limiting multicast join requests via IGMP or MLD on a global or interfaces basis, this is a finding.'
  desc 'fix', 'Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.

R3(config)#int g0/0
R3(config-if)#ip igmp limit 2'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17866r287262_chk'
  tag severity: 'medium'
  tag gid: 'V-216631'
  tag rid: 'SV-216631r856199_rule'
  tag stig_id: 'CISC-RT-000880'
  tag gtitle: 'SRG-NET-000362-RTR-000122'
  tag fix_id: 'F-17862r287263_fix'
  tag 'documentable'
  tag legacy: ['SV-105799', 'V-96661']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
