control 'SV-76665' do
  title 'The layer 2 switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.'
  desc 'If a rogue switch is introduced into the topology and transmits a Bridge Protocol Data Unit (BPDU) with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state. The STP PortFast BPDU guard enhancement allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind the ports that have STP PortFast enabled are not able to influence the STP topology. At the reception of BPDUs, the BPDU guard operation disables the port that has PortFast configured. The BPDU guard transitions the port into errdisable state and sends a log message.'
  desc 'check', 'Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports.

If the switch has not enabled BPDU Guard, this is a finding.'
  desc 'fix', 'Configure the switch to have BPDU Guard enabled on all user-facing or untrusted access switch ports.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62979r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62175'
  tag rid: 'SV-76665r1_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000022'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
