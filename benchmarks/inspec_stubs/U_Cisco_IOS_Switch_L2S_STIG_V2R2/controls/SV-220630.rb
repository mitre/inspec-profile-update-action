control 'SV-220630' do
  title 'The Cisco switch must have Bridge Protocol Data Unit (BPDU) Guard enabled on all user-facing or untrusted access switch ports.'
  desc 'If a rogue switch is introduced into the topology and transmits a BPDU with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state.

The STP PortFast BPDU Guard enhancement allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind the ports that have STP PortFast enabled are not able to influence the STP topology. At the reception of BPDUs, the BPDU Guard operation disables the port that has PortFast configured. The BPDU Guard transitions the port into "errdisable" state and sends a log message.'
  desc 'check', 'Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports as shown in the configuration example below:

interface GigabitEthernet0/0
 spanning-tree bpduguard enable
!
interface GigabitEthernet0/1
 spanning-tree bpduguard enable
…
…
…
interface GigabitEthernet0/9 
 spanning-tree bpduguard enable

If the switch has not enabled BPDU Guard, this is a finding.'
  desc 'fix', 'Enable BPDU Guard on all user-facing or untrusted access switch ports as shown in the configuration example below:

SW1(config)#int range g0/0 - 9
SW1(config-if-range)#spanning-tree bpduguard enable

Note: BPDU Guard can also be enabled globally on all Port Fast-enabled ports by using the spanning-tree portfast bpduguard default command.'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22345r507936_chk'
  tag severity: 'medium'
  tag gid: 'V-220630'
  tag rid: 'SV-220630r539671_rule'
  tag stig_id: 'CISC-L2-000100'
  tag gtitle: 'SRG-NET-000362-L2S-000022'
  tag fix_id: 'F-22334r507937_fix'
  tag 'documentable'
  tag legacy: ['SV-110231', 'V-101127']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
