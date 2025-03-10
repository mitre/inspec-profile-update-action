control 'SV-76663' do
  title 'The layer 2 switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.'
  desc 'Spanning Tree Protocol (STP) does not provide any means for the network administrator to securely enforce the topology of the switched network. Any switch can be the root bridge in a network. However, a more optimal forwarding topology places the root bridge at a specific predetermined location. With the standard STP, any bridge in the network with a lower bridge ID takes the role of the root bridge. The administrator cannot enforce the position of the root bridge but can set the root bridge priority to 0 in an effort to secure the root bridge position.

The root guard feature provides a way to enforce the root bridge placement in the network. If the bridge receives superior STP Bridge Protocol Data Units (BPDUs) on a root guard-enabled port, root guard moves this port to a root-inconsistent STP state and no traffic can be forwarded across this port while it is in this state. To enforce the position of the root bridge it is imperative that root guard is enabled on all ports where the root bridge should never appear.'
  desc 'check', 'Review the switch topology as well as the switch configuration to verify that Root Guard is enabled on all switch ports connecting to access layer switches and hosts.

If the switch has not enabled Root Guard on all switch ports connecting to access layer switches and hosts, this is a finding.'
  desc 'fix', 'Configure the switch to have Root Guard enabled on all switch ports connecting to access layer switches and hosts.'
  impact 0.3
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62977r4_chk'
  tag severity: 'low'
  tag gid: 'V-62173'
  tag rid: 'SV-76663r2_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000021'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68093r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
