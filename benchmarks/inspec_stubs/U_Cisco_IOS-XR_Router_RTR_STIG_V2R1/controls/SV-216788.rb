control 'SV-216788' do
  title 'The Cisco MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'OSPF Example

router ospf 1
 mpls ldp sync

IS-IS Example

router isis 1
 net 49.0001.1234.1600.5531.00
 interface GigabitEthernet0/0/0/1
  address-family ipv4 unicast
   mpls ldp sync

If the router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

OSPF Example

RP/0/0/CPU0:R3(config)#router ospf 1
RP/0/0/CPU0:R3(config-ospf)#mpls ldp sync
RP/0/0/CPU0:R3(config-ospf)#end

IS-IS Example

RP/0/0/CPU0:R3(config)#router isis 1
RP/0/0/CPU0:R3(config-isis)#interface g0/0/0/1
RP/0/0/CPU0:R3(config-isis-if)#address-family ipv4 unicast 
RP/0/0/CPU0:R3(config-isis-if-af)#mpls ldp sync 
RP/0/0/CPU0:R3(config-isis-if-af)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18020r288741_chk'
  tag severity: 'low'
  tag gid: 'V-216788'
  tag rid: 'SV-216788r531087_rule'
  tag stig_id: 'CISC-RT-000600'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-18018r288742_fix'
  tag 'documentable'
  tag legacy: ['V-96783', 'SV-105921']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
