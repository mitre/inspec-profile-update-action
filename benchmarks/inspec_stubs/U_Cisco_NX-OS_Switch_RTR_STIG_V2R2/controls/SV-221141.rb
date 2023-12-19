control 'SV-221141' do
  title 'The Cisco multicast Designated switch (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'ASM can have many sources for the same groups (many-to-many). For many receivers, the path via the RP may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop switch will initiate a switch from the shared tree to a source-specific SPT to obtain lower latencies. This is accomplished by the last-hop switch sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the source).

When the last-hop switch begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message toward the source. The SPT switchover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT switchover occurs.'
  desc 'check', 'Review the DR configuration to verify that the SPT switchover threshold is set to infinity (never switch over). 

ip pim spt-threshold infinity group-list prefix-list SPT_GROUPS

Note: The default behavior is to join the SPT immediately upon the first data packet it receives.

If the DR is not configured set SPT threshold to infinity to minimalize (S, G) state, this is a finding.'
  desc 'fix', 'Configure the DR to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.

Step 1: Configure a prefix list or route map to specify the ASM groups. The example below includes all global ASM groups.

SW1(config)# ip prefix-list SPT_GROUPS permit 233.0.0.0/8

Step 2. Configure the SPT threshold to infinity.

SW1(config)# ip pim spt-threshold infinity group prefix-list SPT_GROUPS 
SW1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22856r409912_chk'
  tag severity: 'medium'
  tag gid: 'V-221141'
  tag rid: 'SV-221141r648772_rule'
  tag stig_id: 'CISC-RT-000890'
  tag gtitle: 'SRG-NET-000362-RTR-000123'
  tag fix_id: 'F-22845r409913_fix'
  tag 'documentable'
  tag legacy: ['SV-111175', 'V-102219']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
