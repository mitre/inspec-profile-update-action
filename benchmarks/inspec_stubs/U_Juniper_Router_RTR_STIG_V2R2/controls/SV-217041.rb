control 'SV-217041' do
  title 'The Juniper perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.'
  desc 'LLDPs are primarily used to obtain protocol addresses of neighboring devices and discover platform capabilities of those devices. Use of SNMP with the LLDP Management Information Base (MIB) allows network management applications to learn the device type and the SNMP agent address of neighboring devices, thereby enabling the application to send SNMP queries to those devices. LLDPs are also media- and protocol-independent as they run over the data link layer; therefore, two systems that support different network-layer protocols can still learn about each other. Allowing LLDP messages to reach external network nodes is dangerous as it provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review all router configurations to ensure LLDP is not enabled external interface. 

protocols {
    …
    …
    …
    lldp {
        advertisement-interval 30;
        interface all;
    }
}

If LLDP is configured globally or on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Disable LLDP on all external interfaces. If necessary, remove the interface all parameter and define all internal interfaces as shown in the example below.

[edit protocols lldp]
delete interface all
set interface ge-0/1/0
set interface ge-0/1/1'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18270r296991_chk'
  tag severity: 'low'
  tag gid: 'V-217041'
  tag rid: 'SV-217041r639663_rule'
  tag stig_id: 'JUNI-RT-000360'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-18268r296992_fix'
  tag 'documentable'
  tag legacy: ['V-90867', 'SV-101077']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
