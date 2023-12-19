control 'SV-220681' do
  title 'The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.'
  desc 'If a rogue switch is introduced into the topology and transmits a Bridge Protocol Data Unit (BPDU) with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state. The STP PortFast BPDU guard enhancement allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind the ports that have STP PortFast enabled are not able to influence the STP topology. At the reception of BPDUs, the BPDU guard operation disables the port that has PortFast configured. The BPDU guard transitions the port into errdisable state and sends a log message.'
  desc 'check', 'Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports as shown in the configuration example below:

interface Ethernet1/1
…
 …
 …
spanning-tree bpduguard enable

interface Ethernet1/2
…
 …
 …
spanning-tree bpduguard enable

If the switch has not enabled BPDU Guard, this is a finding.'
  desc 'fix', 'Configure the switch to have BPDU Guard enabled on all user-facing or untrusted access switch ports as shown in the configuration example below:

SW1(config)# int e1/1 -44
SW1(config-if-range)# spanning-tree bpduguard enable

Note: BPDU guard can also be enabled globally on all edge ports via the following command: 

spanning-tree port type edge bpduguard default'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22396r539094_chk'
  tag severity: 'medium'
  tag gid: 'V-220681'
  tag rid: 'SV-220681r856490_rule'
  tag stig_id: 'CISC-L2-000100'
  tag gtitle: 'SRG-NET-000362-L2S-000022'
  tag fix_id: 'F-22385r539095_fix'
  tag 'documentable'
  tag legacy: ['SV-110337', 'V-101233']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
