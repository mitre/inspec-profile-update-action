control 'SV-207174' do
  title 'The MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the router OSPF or IS-IS configuration.

Verify that LDP will synchronize with the link-state routing protocol.

If the router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7435r382610_chk'
  tag severity: 'low'
  tag gid: 'V-207174'
  tag rid: 'SV-207174r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000003'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7435r382611_fix'
  tag 'documentable'
  tag legacy: ['SV-92993', 'V-78287']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
