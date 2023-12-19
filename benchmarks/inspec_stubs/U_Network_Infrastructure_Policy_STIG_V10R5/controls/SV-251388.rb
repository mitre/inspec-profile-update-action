control 'SV-251388' do
  title 'Protocol Independent Multicast (PIM) must be disabled on all router interfaces that are not required to support multicast routing.'
  desc 'PIM is a routing protocol that is used by the IP core for forwarding multicast traffic. PIM operates independent of any particular IP routing protocol but makes use of the IP unicast routing table--PIM does not keep a separate multicast routing table. The multicast tree is built by first allowing a flood of traffic from the source to every dense mode router in the network. For a brief time, unnecessary traffic is allowed. As each router receives traffic for the group, it will decide whether it has active recipients wanting to receive the multicast data. If so, the router will let the flow continue. If no hosts have registered for the multicast group, the router sends a prune message to its neighbor toward the source. That branch of the tree is then pruned off so that the unnecessary traffic does not continue. Dense mode is viewed as a "flood and prune" implementation. With PIM Sparse Mode (PIM-SM), the multicast tree is not extended to a router unless a local host has already joined the group. The multicast tree is built by beginning with group members at the end leaf nodes and extending back toward a central root point--the tree is built from the bottom up. In either case, if an interface is not going to be supporting any of the multicast traffic--that is, join a multicast tree, PIM should be disabled.'
  desc 'check', 'By default, multicast is disabled globally as well as on all interfaces. Multicast routing is enabled on a router with the global command ip multicast-routing. PIM is enabled on an interface with either of the following commands: ip pim sparse-mode, ip pim dense-mode, ip pim sparse-dense-mode. If the global command ip multicast-routing is defined, review all interface configurations and verify that only the required interfaces are enabled for PIM. The following is a sample configuration with multicast routing enabled and PIM enabled on an interface.

ip multicast-routing
!
interface FastEthernet0/0 
ip pim sparse-mode

If PIM is not disabled on interfaces that are not supporting multicast, this is a finding.'
  desc 'fix', 'The router administrator will disable PIM on all router interfaces that are not required to support multicast routing.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54823r806117_chk'
  tag severity: 'medium'
  tag gid: 'V-251388'
  tag rid: 'SV-251388r806119_rule'
  tag stig_id: 'NET2006'
  tag gtitle: 'NET2006'
  tag fix_id: 'F-54776r806118_fix'
  tag 'documentable'
  tag legacy: ['V-66365', 'SV-80855']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
