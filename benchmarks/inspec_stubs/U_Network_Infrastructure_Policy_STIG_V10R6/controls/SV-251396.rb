control 'SV-251396' do
  title 'The number of mroute states resulting from Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) membership reports must be limited.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) membership report to the Designated Router (DR). In a PIM Sparse Mode network, the DR will send a PIM Join message for the group to the Rendezvous Point (RP). Without any form of admission control, this can pose a security risk to the entire multicast domain, specifically the multicast routers along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP (IPv4) or MLD (IPv6) flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

If the DR is not limiting multicast join requests via IGMP or MLD, this is a finding.

The following is a PIM sparse mode DR configuration example that limits the number of IGMP join requests on both a global and a per-interface basis

ip multicast-routing
ip igmp limit 80
! 
interface FastEthernet 0/1
description User LAN121
ip address 192.168.122.1 255.255.255.0
ip pim sparse-mode 
ip igmp limit 50
!
interface FastEthernet 0/2
description User LAN122
ip address 192.168.122.1 255.255.255.0
ip pim sparse-mode 
ip igmp limit 50

Note: If both global and per interface state limiters are configured, the limits configured for per interface state limiters are still enforced but are constrained by the global limit.'
  desc 'fix', 'Configure the Designated Router (DR) on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54831r806141_chk'
  tag severity: 'medium'
  tag gid: 'V-251396'
  tag rid: 'SV-251396r853657_rule'
  tag stig_id: 'NET2014'
  tag gtitle: 'NET2014'
  tag fix_id: 'F-54784r806142_fix'
  tag 'documentable'
  tag legacy: ['V-66389', 'SV-80879']
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']
end
