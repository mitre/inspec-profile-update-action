control 'SV-251397' do
  title 'The number of source-group (SG) states must be limited within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'Any Source Multicast (ASM) can have many sources for the same groups (many-to-many). For many receivers, the path via the Rendezvous Point (RP) may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop router will initiate a switch from the shared tree to a source-specific shortest-path tree (SPT) to obtain lower latencies. This is accomplished by the last-hop router sending an (S, G) PIM Join towards S (the source). When the last-hop router begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message towards the source. The SPT switchover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT switchover occurs.'
  desc 'check', 'Review the multicast last-hop router configuration to verify that the SPT switchover threshold is increased (default is 0) or set to infinity (never switch over). The following is a PIM sparse mode last-hop router configuration example that will disable the SPT switchover for all multicast groups:

ip multicast-routing
ip pim spt-threshold infinity

If any multicast router is not configured to increase the SPT threshold or set it to infinity to minimalize (S,G) state, this is a finding.'
  desc 'fix', 'Configure the multicast router to increase the SPT threshold or set it to infinity to minimalize (S,G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54832r806144_chk'
  tag severity: 'medium'
  tag gid: 'V-251397'
  tag rid: 'SV-251397r806146_rule'
  tag stig_id: 'NET2015'
  tag gtitle: 'NET2015'
  tag fix_id: 'F-54785r806145_fix'
  tag 'documentable'
  tag legacy: ['V-66391', 'SV-80881']
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']
end
