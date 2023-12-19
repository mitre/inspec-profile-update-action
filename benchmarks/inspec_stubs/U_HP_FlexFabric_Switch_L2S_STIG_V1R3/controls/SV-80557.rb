control 'SV-80557' do
  title 'The HP FlexFabric Switch must have STP Loop Protection enabled all non-designated STP switch ports.'
  desc 'The Spanning Tree Protocol (STP) loop Protection feature provides additional protection against STP loops. An STP loop is created when an STP blocking port in a redundant topology erroneously transitions to the forwarding state. In its operation, STP relies on continuous reception and transmission of BPDUs based on the port role. The designated port transmits BPDUs, and the non-designated port receives BPDUs. When one of the ports in a physically redundant topology no longer receives BPDUs, the STP conceives that the topology is loop free. Eventually, the blocking port from the alternate or backup port becomes a designated port and moves to a forwarding state. This situation creates a loop. The loop Protection feature makes additional checks. If BPDUs are not received on a non-designated port and loop guard is enabled, that port is moved into the STP loop-inconsistent blocking state.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that STP Loop Protection is enabled.

If STP Loop Protection is not configured globally or at a minimum on non-designated STP ports, this is a finding.

[HPinterface Ten-GigabitEthernet1/0/8]
 port link-mode bridge
 stp loop-protection'
  desc 'fix', 'Configure the HP FlexFabric Switch to have STP Loop Protection enabled globally or at a minimum on all non-designated switch ports.

[HPinterface Ten-GigabitEthernet1/0/8]
stp loop-protection'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66067'
  tag rid: 'SV-80557r1_rule'
  tag stig_id: 'HFFS-L2-000012'
  tag gtitle: 'SRG-NET-000362-L2S-000023'
  tag fix_id: 'F-72143r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
