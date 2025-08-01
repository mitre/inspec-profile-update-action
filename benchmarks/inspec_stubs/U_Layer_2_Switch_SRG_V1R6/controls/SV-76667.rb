control 'SV-76667' do
  title 'The layer 2 switch must have STP Loop Guard enabled on all non-designated STP switch ports.'
  desc 'The Spanning Tree Protocol (STP) loop guard feature provides additional protection against STP loops. An STP loop is created when an STP blocking port in a redundant topology erroneously transitions to the forwarding state. In its operation, STP relies on continuous reception and transmission of BPDUs based on the port role. The designated port transmits BPDUs, and the non-designated port receives BPDUs. When one of the ports in a physically redundant topology no longer receives BPDUs, the STP conceives that the topology is loop free. Eventually, the blocking port from the alternate or backup port becomes a designated port and moves to a forwarding state. This situation creates a loop. The loop guard feature makes additional checks. If BPDUs are not received on a non-designated port and loop guard is enabled, that port is moved into the STP loop-inconsistent blocking state.'
  desc 'check', 'Review the switch configuration to verify that STP Loop Guard is enabled.

If STP Loop Guard is not configured globally or on non-designated STP ports, this is a finding.'
  desc 'fix', 'Configure the switch to have STP Loop Guard enabled globally or at a minimum on all non-designated STP switch ports.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62981r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62177'
  tag rid: 'SV-76667r1_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000023'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
