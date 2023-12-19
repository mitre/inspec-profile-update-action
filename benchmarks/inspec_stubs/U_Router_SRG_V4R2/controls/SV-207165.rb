control 'SV-207165' do
  title 'The perimeter router must be configured to have Link Layer Discovery Protocols (LLDPs) disabled on all external interfaces.'
  desc 'LLDPs are primarily used to obtain protocol addresses of neighboring devices and discover platform capabilities of those devices. Use of SNMP with the LLDP Management Information Base (MIB) allows network management applications to learn the device type and the SNMP agent address of neighboring devices, thereby enabling the application to send SNMP queries to those devices. LLDPs are also media- and protocol-independent as they run over the data link layer; therefore, two systems that support different network-layer protocols can still learn about each other. Allowing LLDP messages to reach external network nodes is dangerous as it provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review all router configurations to ensure LLDPs are not included in the global configuration or LLDPs are not included for each active external interface. Examples of LLDPs are Cisco Discovery Protocol (CDP), Link Layer Discovery Protocol (LLDP), and Link Layer Discovery Protocol - Media Endpoint Discovery (LLDP-MED).

If LLDPs are configured globally or on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Disable LLDPs on all external interfaces.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7426r382523_chk'
  tag severity: 'low'
  tag gid: 'V-207165'
  tag rid: 'SV-207165r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000111'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7426r382524_fix'
  tag 'documentable'
  tag legacy: ['SV-92955', 'V-78249']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
