control 'SV-256050' do
  title 'The MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the Arista router OSPF or IS-IS configuration.

ISIS configuration example:

router isis 1
   mpls ldp sync default
  
OSPF configuration example:

router ospf 1
   mpls ldp sync default

Verify LDP will synchronize with the link-state routing protocol.

interface Loopback1
   description MPLS-LDP-Router-ID
   ip address 10.1.129.94/32
   mpls ldp igp sync
   ip ospf area 0.0.0.5

If the Arista router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the Arista MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

ISIS configuration example:

P-Router-EOS(config)#router isis 1
P-Router-EOS(config-router-isis)#mpls ldp sync default

OSPF configuration example:

LEAF-1A(config-mpls-ldp)#router ospf 1
LEAF-1A(config-router-ospf)#mpls ldp sync default

Configure LDP to synchronize with the link-state routing protocol.

LEAF-1A(config)#interface Loopback1
LEAF-1A(config-if-Lo0)#erface Loopback1
LEAF-1A(config-if-Lo0)#description MPLS-LDP-Router-ID
LEAF-1A(config-if-Lo0)#ip address 10.1.129.94/32
LEAF-1A(config-if-Lo0)#mpls ldp igp sync
LEAF-1A(config-if-Lo0)#ip ospf area 0.0.0.5'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59726r882490_chk'
  tag severity: 'low'
  tag gid: 'V-256050'
  tag rid: 'SV-256050r882492_rule'
  tag stig_id: 'ARST-RT-000710'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-59669r882491_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
