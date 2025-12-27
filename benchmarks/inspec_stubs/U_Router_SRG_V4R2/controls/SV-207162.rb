control 'SV-207162' do
  title 'The multicast Designated Router (DR) must be configured to increase the shortest-path tree (SPT) threshold or set it to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'ASM can have many sources for the same groups (many-to-many). For many receivers, the path via the RP may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop router will initiate a switch from the shared tree to a source-specific SPT to obtain lower latencies. This is accomplished by the last-hop router sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the source).

When the last-hop router begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message toward the source. The SPT switchover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT switchover occurs.'
  desc 'check', 'Review the multicast last-hop router configuration to verify that the SPT switchover threshold is increased (default is "0") or set to infinity (never switch over). 

If any multicast router is not configured to increase the SPT threshold or set to infinity to minimalize (S, G) state, this is a finding.'
  desc 'fix', 'Configure the multicast router to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7423r382514_chk'
  tag severity: 'medium'
  tag gid: 'V-207162'
  tag rid: 'SV-207162r648772_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000123'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7423r382515_fix'
  tag 'documentable'
  tag legacy: ['SV-93043', 'V-78337']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
