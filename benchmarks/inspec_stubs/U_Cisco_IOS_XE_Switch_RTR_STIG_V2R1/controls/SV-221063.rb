control 'SV-221063' do
  title 'The Cisco multicast Designated switch (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'ASM can have many sources for the same groups (many-to-many). For many receivers, the path via the RP may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop switch will initiate a switch from the shared tree to a source-specific SPT to obtain lower latencies. This is accomplished by the last-hop switch sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the source).

When the last-hop switch begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message toward the source. The SPT switchover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT switchover occurs.'
  desc 'check', 'Review the DR configuration to verify that the SPT switchover threshold is increased (default is "0") or set to infinity (never switch over). 

ip pim rp-address 10.2.2.2
ip pim spt-threshold infinity

If the DR is not configured to increase the SPT threshold or set to infinity to minimalize (S, G) state, this is a finding.'
  desc 'fix', 'Configure the DR to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.

SW2(config)#ip pim spt-threshold infinity'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22778r408983_chk'
  tag severity: 'medium'
  tag gid: 'V-221063'
  tag rid: 'SV-221063r622190_rule'
  tag stig_id: 'CISC-RT-000890'
  tag gtitle: 'SRG-NET-000362-RTR-000123'
  tag fix_id: 'F-22767r408984_fix'
  tag 'documentable'
  tag legacy: ['V-101843', 'SV-110947']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
