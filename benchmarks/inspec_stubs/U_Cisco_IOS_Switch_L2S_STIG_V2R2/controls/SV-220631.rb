control 'SV-220631' do
  title 'The Cisco switch must have Spanning Tree Protocol (STP) Loop Guard enabled.'
  desc 'The STP loop guard feature provides additional protection against STP loops. An STP loop is created when an STP blocking port in a redundant topology erroneously transitions to the forwarding state. In its operation, STP relies on continuous reception and transmission of BPDUs based on the port role. 

The designated port transmits BPDUs, and the non-designated port receives BPDUs. When one of the ports in a physically redundant topology no longer receives BPDUs, the STP conceives that the topology is loop free. Eventually, the blocking port from the alternate or backup port becomes a designated port and moves to a forwarding state. This situation creates a loop. The Loop Guard feature makes additional checks. If BPDUs are not received on a non-designated port and loop guard is enabled, that port is moved into the STP loop-inconsistent blocking state.'
  desc 'check', 'Review the switch configuration to verify that STP Loop Guard is enabled as shown in the configuration example below:

hostname SW2
…
…
…
spanning-tree mode pvst
spanning-tree loopguard default

If STP Loop Guard is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to have STP Loop Guard enabled via the spanning-tree loopguard default global command.'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22346r507939_chk'
  tag severity: 'medium'
  tag gid: 'V-220631'
  tag rid: 'SV-220631r539671_rule'
  tag stig_id: 'CISC-L2-000110'
  tag gtitle: 'SRG-NET-000362-L2S-000023'
  tag fix_id: 'F-22335r507940_fix'
  tag 'documentable'
  tag legacy: ['SV-110233', 'V-101129']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
