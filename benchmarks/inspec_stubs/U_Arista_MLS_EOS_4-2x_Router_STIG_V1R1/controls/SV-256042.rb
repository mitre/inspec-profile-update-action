control 'SV-256042' do
  title 'The Arista perimeter router must be configured to have Link Layer Discovery Protocols (LLDPs) disabled on all external interfaces.'
  desc 'LLDPs are primarily used to obtain protocol addresses of neighboring devices and discover platform capabilities of those devices. Use of SNMP with the LLDP Management Information Base (MIB) allows network management applications to learn the device type and the SNMP agent address of neighboring devices, thereby enabling the application to send SNMP queries to those devices. LLDPs are also media- and protocol-independent as they run over the data link layer; therefore, two systems that support different network-layer protocols can still learn about each other. Allowing LLDP messages to reach external network nodes is dangerous as it provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review all Arista router configurations to ensure LLDPs are not included in the global configuration or LLDPs are not included for each active external interface. Examples of LLDPs are Cisco Discovery Protocol (CDP), Link Layer Discovery Protocol (LLDP), and Link Layer Discovery Protocol - Media Endpoint Discovery (LLDP-MED).

Disable LLDP on external interface.

int ethernet 3
 no lldp transmit
 no lldp receive

On Arista multi-layer routers, the LLDP can be disabled globally.

no lldp run

If LLDPs are configured globally or on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Disable LLDPs on all external interfaces.

LEAF-1A(config)#int ethernet 3
LEAF-1A(config-if-Et3)#no lldp transmit
LEAF-1A(config-if-Et3)#no lldp receive

Disable LLDP globally.

LEAF-1A(config)#no lldp run'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59718r882466_chk'
  tag severity: 'low'
  tag gid: 'V-256042'
  tag rid: 'SV-256042r882468_rule'
  tag stig_id: 'ARST-RT-000630'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-59661r882467_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
