control 'SV-221034' do
  title 'The Cisco MPLS switch must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the switch begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the switch continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the switch OSPF or IS-IS configuration and verify that LDP will synchronize with the link-state routing protocol as shown in the example below:

OSPF Example:

router ospf 1
 mpls ldp sync

IS-IS Example:

router isis
 mpls ldp sync
 net 49.0001.1234.1600.5531.00

If the switch is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS switch to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

OSPF Example:

SW2(config)#router ospf 1
SW2(config-switch)#mpls ldp sync

IS-IS Example:

SW1(config)#router isis
SW1(config-switch)#mpls ldp sync'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22749r408896_chk'
  tag severity: 'low'
  tag gid: 'V-221034'
  tag rid: 'SV-221034r622190_rule'
  tag stig_id: 'CISC-RT-000600'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-22738r408897_fix'
  tag 'documentable'
  tag legacy: ['SV-110889', 'V-101785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
