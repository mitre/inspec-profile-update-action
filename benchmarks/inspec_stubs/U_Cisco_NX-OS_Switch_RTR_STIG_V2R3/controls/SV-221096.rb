control 'SV-221096' do
  title 'The Cisco perimeter switch must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.'
  desc 'LLDP is a neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. LLDP is media-and-protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing LLDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'Step 1: Verify LLDP is not enabled globally via the command feature lldp.

By default the LLDP feature is not enabled. If LLDP is enabled, proceed to Step 2.

Step 2: Verify LLDP is not enabled on any external interface as shown in the example below:

interface Ethernet2/2
 description link to DISN
 no switchport
 no lldp transmit

Note: LLDP is enabled by default on all interfaces once it is enabled globally; hence the command lldp transmit will not be visible on the interface configuration.

If LLDP transmit is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable LLDP transmit on all external interfaces as shown in the example below:

SW2(config)# int e2/2
SW2(config-if)# no lldp transmit 
SW2(config-if)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22811r409777_chk'
  tag severity: 'low'
  tag gid: 'V-221096'
  tag rid: 'SV-221096r856650_rule'
  tag stig_id: 'CISC-RT-000360'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-22800r409778_fix'
  tag 'documentable'
  tag legacy: ['SV-111011', 'V-101907']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
