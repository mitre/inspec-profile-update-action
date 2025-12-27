control 'SV-80847' do
  title 'Label Distribution Protocol (LDP) must be synchronized with the Interior Gateway Protocol (IGP) to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the router configuration and verify that the "mpls ldp sync" command is configured on the IS-IS or OSPF configuration as shown in the following example: 

mpls ip
mpls label protocol ldp
!
interface POS0/3
ip router isis
mpls ip
...
...
...
router isis
mpls ldp sync

If not all MPLS routers synchronize IGP and LDP, this is a finding.

Note: If the LDP peer is reachable, the IGP waits indefinitely (by default) for synchronization to be achieved. To limit the length of time the IGP session must wait, enter the "mpls ldp igp sync holddown" command. If the LDP peer is not reachable, the IGP establishes the adjacency to enable the LDP session to be established.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67003r1_chk'
  tag severity: 'low'
  tag gid: 'V-66357'
  tag rid: 'SV-80847r1_rule'
  tag stig_id: 'NET2002'
  tag gtitle: 'NET2002'
  tag fix_id: 'F-72433r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001549']
  tag nist: ['AC-4']
end
