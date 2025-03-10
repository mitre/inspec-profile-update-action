control 'SV-221062' do
  title 'The Cisco multicast Designated switch (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an IGMP or MLD membership report to the DR. In a Protocol Independent Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the group to the RP. Without any form of admission control, this can pose a security risk to the entire multicast domain, specifically the multicast switches along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP or MLD flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

Verify IGMP limits have been configured globally or on each host-facing layer 3 and VLAN interface via the ip igmp limit command as shown in the example below:

interface Vlan3
 ip address 10.3.3.3 255.255.255.0
…
 …
 …
ip igmp limit nn

If the DR is not limiting multicast join requests via IGMP or MLD on a global or interfaces basis, this is a finding.'
  desc 'fix', 'Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.

SW2(config)#int vlan3
SW2(config-if)#ip igmp limit 2'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22777r408980_chk'
  tag severity: 'medium'
  tag gid: 'V-221062'
  tag rid: 'SV-221062r856425_rule'
  tag stig_id: 'CISC-RT-000880'
  tag gtitle: 'SRG-NET-000362-RTR-000122'
  tag fix_id: 'F-22766r408981_fix'
  tag 'documentable'
  tag legacy: ['SV-110945', 'V-101841']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
