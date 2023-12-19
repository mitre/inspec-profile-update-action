control 'SV-216764' do
  title 'The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.'
  desc 'LLDP is a neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. LLDP is media- and protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing LLDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify LLDP is not enabled globally via the command  

lldp

By default LLDP is not enabled globally. If LLDP is enabled, proceed to step 2.

Step 2: Verify LLDP transmit is disabled on any external interface as shown in the example below.

interface GigabitEthernet0/0/0/1
 ipv4 address x.1.34.3 255.255.255.252
 lldp
  transmit disable

Note: LLDP is enabled by default on all interfaces once it is enabled globally; hence the commands lldp transmit and lldp receive will not be visible on the interface configuration.

If LLDP transmit is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable LLDP transmit on all external interfaces as shown in the example below.

RP/0/0/CPU0:R3(config)#interface g0/0/0/1
RP/0/0/CPU0:R3(config-if)#lldp transmit disable'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17996r288675_chk'
  tag severity: 'low'
  tag gid: 'V-216764'
  tag rid: 'SV-216764r856442_rule'
  tag stig_id: 'CISC-RT-000360'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-17994r288676_fix'
  tag 'documentable'
  tag legacy: ['SV-105873', 'V-96735']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
