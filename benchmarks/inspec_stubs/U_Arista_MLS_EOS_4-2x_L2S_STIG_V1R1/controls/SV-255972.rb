control 'SV-255972' do
  title 'The Arista MLS switch must have STP Loop Guard enabled on all nondesignated STP switch ports.'
  desc 'The Spanning Tree Protocol (STP) loop guard feature provides additional protection against STP loops. An STP loop is created when an STP blocking port in a redundant topology erroneously transitions to the forwarding state. In its operation, STP relies on continuous reception and transmission of BPDUs based on the port role. The designated port transmits BPDUs, and the nondesignated port receives BPDUs. When one of the ports in a physically redundant topology no longer receives BPDUs, the STP conceives that the topology is loop free. Eventually, the blocking port from the alternate or backup port becomes a designated port and moves to a forwarding state. This situation creates a loop. The loop guard feature makes additional checks. If BPDUs are not received on a nondesignated port and loop guard is enabled, that port is moved into the STP loop-inconsistent blocking state.'
  desc 'check', 'Review the Arista MLS switch configuration to verify that STP Loop Guard is enabled. It can be enabled globally or applied to an interface.

switch# sh run | sec spanning-tree
spanning-tree guard loop default

Or,

interface Ethernet6
    spanning-tree guard loop

If STP Loop Guard is not configured globally or on nondesignated STP ports, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch for STP Loop Guard globally with the following command:

switch(config)#spanning-tree guard loop default
switch(config)#

Alternatively, configure Loop Guard on each interface:

switch(config-if-Eth6)# spanning-tree guard loop'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59648r882256_chk'
  tag severity: 'medium'
  tag gid: 'V-255972'
  tag rid: 'SV-255972r882258_rule'
  tag stig_id: 'ARST-L2-000070'
  tag gtitle: 'SRG-NET-000362-L2S-000023'
  tag fix_id: 'F-59591r882257_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
