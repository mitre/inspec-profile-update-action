control 'SV-110335' do
  title 'The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.'
  desc 'Spanning Tree Protocol (STP) does not provide any means for the network administrator to securely enforce the topology of the switched network. Any switch can be the root bridge in a network. However, a more optimal forwarding topology places the root bridge at a specific predetermined location. With the standard STP, any bridge in the network with a lower bridge ID takes the role of the root bridge. The administrator cannot enforce the position of the root bridge but can set the root bridge priority to 0 in an effort to secure the root bridge position.

The root guard feature provides a way to enforce the root bridge placement in the network. If the bridge receives superior STP Bridge Protocol Data Units (BPDUs) on a root guard-enabled port, root guard moves this port to a root-inconsistent STP state and no traffic can be forwarded across this port while it is in this state. To enforce the position of the root bridge it is imperative that root guard is enabled on all ports where the root bridge should never appear.'
  desc 'check', 'Review the switch topology as well as the configuration to verify that Root Guard is enabled on all switch ports connecting to access layer switches and hosts.

interface Ethernet1/1
…
 …
 …
spanning-tree guard root

interface Ethernet1/2
…
 …
 …
spanning-tree guard root

interface Ethernet1/3
…
 …
 …
spanning-tree guard root

If the switch has not enabled Root Guard on all switch ports connecting to access layer switches and hosts, this is a finding.'
  desc 'fix', 'Configure the switch to have Root Guard enabled on all ports connecting to access layer switches and hosts.

SW1(config)# int e1/1 – 44
SW1(config-if-range)# spanning-tree guard root
SW1(config-if-range)# end'
  impact 0.3
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100111r1_chk'
  tag severity: 'low'
  tag gid: 'V-101231'
  tag rid: 'SV-110335r1_rule'
  tag stig_id: 'CISC-L2-000090'
  tag gtitle: 'SRG-NET-000362-L2S-000021'
  tag fix_id: 'F-106935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
