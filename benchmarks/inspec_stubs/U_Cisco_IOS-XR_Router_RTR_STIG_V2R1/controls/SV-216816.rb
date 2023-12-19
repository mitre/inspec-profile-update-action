control 'SV-216816' do
  title 'The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.'
  desc 'The current multicast paradigm can let any host join any multicast group at any time by sending an IGMP or MLD membership report to the DR. In a Protocol Independent Multicast (PIM) Sparse Mode network, the DR will send a PIM Join message for the group to the RP. Without any form of admission control, this can pose a security risk to the entire multicast domain - specifically the multicast routers along the shared tree from the DR to the RP that must maintain the mroute state information for each group join request. Hence, it is imperative that the DR is configured to limit the number of mroute state information that must be maintained to mitigate the risk of IGMP or MLD flooding.'
  desc 'check', 'Review the DR configuration to verify that it is limiting the number of mroute states via IGMP or MLD.

Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command as shown in the example.

router igmp
 interface GigabitEthernet0/0/0/0
  access-group IGMP_JOIN_FILTER
 !
 interface GigabitEthernet0/0/0/1
  access-group IGMP_JOIN_FILTER
 !
 maximum groups 200

!Note: After the maximum groups value is met, all additional memberships learned are ignored. If not configured, the default is 5000 which would be an overage for a small to average size multicast deployment. 

If the DR is not limiting multicast join requests via IGMP or MLD on a global or interfaces basis, this is a finding.'
  desc 'fix', 'Configure the DR on a global or interface basis to limit the number of mroute states resulting from IGMP or MLD membership reports.

RP/0/0/CPU0:R5(config)#router igmp 
RP/0/0/CPU0:R2(config-igmp)#maximum groups 200
RP/0/0/CPU0:R5(config-igmp)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18048r288822_chk'
  tag severity: 'medium'
  tag gid: 'V-216816'
  tag rid: 'SV-216816r531087_rule'
  tag stig_id: 'CISC-RT-000880'
  tag gtitle: 'SRG-NET-000362-RTR-000122'
  tag fix_id: 'F-18046r288823_fix'
  tag 'documentable'
  tag legacy: ['SV-105977', 'V-96839']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
