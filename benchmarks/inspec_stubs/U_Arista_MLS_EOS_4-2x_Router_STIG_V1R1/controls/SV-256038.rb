control 'SV-256038' do
  title 'The Arista multicast Designated Router (DR) must be configured to increase the shortest-path tree (SPT) threshold or set it to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'ASM can have many sources for the same groups (many-to-many). For many receivers, the path via the RP may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop router will initiate a router from the shared tree to a source-specific SPT to obtain lower latencies. This is accomplished by the last-hop router sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the source).

When the last-hop router begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message toward the source. The SPT routerover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT routerover occurs.'
  desc 'check', 'Review the Arista multicast last-hop router configuration to verify the SPT routerover threshold is increased (default is "0") or set to infinity (never router over). 

router pim sparse-mode
   ipv4
      spt threshold infinity

If any Arista multicast router is not configured to increase the SPT threshold or set to infinity to minimalize (S, G) state, this is a finding.'
  desc 'fix', 'Configure the Arista multicast router to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.

LEAF-1A(config)#router pim sparse-mode 
LEAF-1A(config-router-pim-sparse)#ipv4
LEAF-1A(config-router-pim-sparse-ipv4)#spt threshold infinity'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59714r882454_chk'
  tag severity: 'medium'
  tag gid: 'V-256038'
  tag rid: 'SV-256038r882456_rule'
  tag stig_id: 'ARST-RT-000590'
  tag gtitle: 'SRG-NET-000362-RTR-000123'
  tag fix_id: 'F-59657r882455_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
