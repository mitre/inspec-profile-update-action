control 'SV-253956' do
  title 'The Juniper EX switch must be configured to enable BPDU Protection on all user-facing or untrusted access switch ports.'
  desc 'If a rogue switch is introduced into the topology and transmits a Bridge Protocol Data Unit (BPDU) with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state. BPDU Protection  allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind interfaces that have BPDU Protection enabled are not able to influence the STP topology. At the reception of BPDUs,  BPDU Protection disables the port and logs the condition.'
  desc 'check', 'Review the switch configuration to verify that BPDU Protection is enabled on all user-facing or untrusted access switch interfaces.

BPDU Protection discards all BPDUs received on a configured interface and stops forwarding on that interface. In contrast, Root Protection discards only superior root BPDUs but accepts remaining BPDU types. Verify BDPU Protection (bpdu-block-on-edge) and the edge interfaces where no BPDUs are expected.

[protocols]
mstp {
    bpdu-block-on-edge;
    interface <interface name> {
        edge;
    }
}
Note: Configuring BPDU Protection and Root Protection on the same interface is supported, but redundant because BPDU protection includes Root Protection.

If the switch has not enabled BPDU Protection, this is a finding.'
  desc 'fix', 'Configure the switch to have BPDU Protection enabled on all user-facing or untrusted access switch interfaces.

set protocols mstp bpdu-block-on-edge
set protocols mstp interface <interface name> edge

Note: Configuring BPDU Protection and Root Protection on the same interface is supported, but redundant because BPDU protection includes Root Protection.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57408r843899_chk'
  tag severity: 'medium'
  tag gid: 'V-253956'
  tag rid: 'SV-253956r843901_rule'
  tag stig_id: 'JUEX-L2-000090'
  tag gtitle: 'SRG-NET-000362-L2S-000022'
  tag fix_id: 'F-57359r843900_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
