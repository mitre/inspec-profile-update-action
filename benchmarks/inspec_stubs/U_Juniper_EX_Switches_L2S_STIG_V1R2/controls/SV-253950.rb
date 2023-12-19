control 'SV-253950' do
  title 'The Juniper layer 2 switch must be configured to disable all dynamic VLAN registration protocols.'
  desc 'Dynamic VLAN registration protocols provide centralized management of VLAN domains, which can reduce administration in a switched network. Interfaces are assigned to VLANs and the VLAN is dynamically registered on the trunked interface. Removing the last active interface from the VLAN automatically prunes the VLAN from the trunked interface, preserving bandwidth. Member switches remain synchronized via the exchange of Protocol Data Units (PDU). Protocols like Cisco VLAN Trunk Protocol (VTP) and IEEE 802.1ak Multiple VLAN Registration Protocol (MVRP) permit dynamically registering/de-registering VLANs on trunked interfaces. Without authentication, forged PDUs can allow access to previously inaccessible VLANs, or inclusion of unauthorized VLANs or switches. Only VTP currently supports authentication.'
  desc 'check', 'Review the switch configuration to verify if dynamic VLAN registration protocols are enabled. If dynamic VLAN registration protocols are enabled, verify that authentication has been configured.

Juniper switches do not support VTP. Although Juniper switches support MVRP, it is disabled by default (there is no [edit protocols mvrp] stanza). Verify MVRP is not enabled as shown below.

[edit protocols]
mvrp {
    interface <name>;
}

If dynamic VLAN registration protocols have been configured on the switch and are not authenticating messages with a hash function using the most secured cryptographic algorithm available, this is a finding.'
  desc 'fix', 'Configure the switch to disable all dynamic VLAN registration protocols.

delete protocols mvrp'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57402r843881_chk'
  tag severity: 'medium'
  tag gid: 'V-253950'
  tag rid: 'SV-253950r843883_rule'
  tag stig_id: 'JUEX-L2-000030'
  tag gtitle: 'SRG-NET-000168-L2S-000019'
  tag fix_id: 'F-57353r843882_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
