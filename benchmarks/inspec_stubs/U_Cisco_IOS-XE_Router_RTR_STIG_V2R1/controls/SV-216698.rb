control 'SV-216698' do
  title 'The Cisco MPLS router must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the router OSPF or IS-IS configuration and verify that LDP will synchronize with the link-state routing protocol as shown in the example below:

OSPF Example:

router ospf 1
 mpls ldp sync

IS-IS Example:

router isis
 mpls ldp sync
 net 49.0001.1234.1600.5531.00

If the router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

OSPF Example:

R2(config)#router ospf 1
R2(config-router)#mpls ldp sync

IS-IS Example:

R5(config)#router isis
R5(config-router)#mpls ldp sync'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17931r288039_chk'
  tag severity: 'low'
  tag gid: 'V-216698'
  tag rid: 'SV-216698r531086_rule'
  tag stig_id: 'CISC-RT-000600'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-17929r288040_fix'
  tag 'documentable'
  tag legacy: ['V-96969', 'SV-106107']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
