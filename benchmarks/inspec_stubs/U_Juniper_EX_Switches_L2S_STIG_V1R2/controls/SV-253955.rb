control 'SV-253955' do
  title 'The Juniper EX switch must be configured to enable Root Protection on all interfaces connecting to access layer switches and hosts.'
  desc 'Spanning Tree Protocol (STP) does not provide any means for the network administrator to securely enforce the topology of the switched network. Any switch can be the root bridge in a network. However, a more optimal forwarding topology places the root bridge at a specific predetermined location. With the standard STP, any bridge in the network with a lower bridge ID takes the role of the root bridge. The administrator cannot enforce the position of the root bridge but can set the root bridge priority to 0 in an effort to secure the root bridge position.

The Root Protection feature provides a way to enforce the root bridge placement in the network. If the bridge receives superior STP Bridge Protocol Data Units (BPDUs) on a Root Protection-enabled interface, Root Protection ignores the superior BPDU and places the interface into block and a root-inconsistent state. To enforce the position of the root bridge it is imperative that Root Protection is enabled on all interfaces where the root bridge should never appear.'
  desc 'check', 'Review the switch topology as well as the switch configuration to verify that Root Protection is enabled on all interfaces connecting to access layer switches and hosts.

[edit protocols]
mstp {
    interface <interface name> {
        no-root-port;
    }
}
Note: Root Protection and Loop Protection are mutually exclusive and cannot be simultaneously configured on the same interface.

If the switch has not enabled Root Protection on all interfaces connecting to access layer switches and hosts, this is a finding.'
  desc 'fix', 'Configure the switch to have Root Protection enabled on all switch ports connecting to access layer switches and hosts using trunked interfaces.

set protocols mstp interface <interface name> no-root-port

Note: Root Protection and Loop Protection are mutually exclusive and cannot be simultaneously configured on the same interface.'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57407r843896_chk'
  tag severity: 'low'
  tag gid: 'V-253955'
  tag rid: 'SV-253955r843898_rule'
  tag stig_id: 'JUEX-L2-000080'
  tag gtitle: 'SRG-NET-000362-L2S-000021'
  tag fix_id: 'F-57358r843897_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
