control 'SV-216674' do
  title 'The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.'
  desc 'LLDP is a neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. LLDP is media-and-protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing LLDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify LLDP is not enabled globally via the command.  

lldp run

By default LLDP is not enabled globally. If LLDP is enabled, proceed to step 2.

Step 2: Verify LLDP is not enabled on any external interface as shown in the example below:

interface GigabitEthernet0/1
 ip address x.1.12.1 255.255.255.252
 no lldp transmit

Note: LLDP is enabled by default on all interfaces once it is enabled globally; hence the command "lldp transmit" will not be visible on the interface configuration.

If LLDP transmit is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable LLDP transmit on all external interfaces as shown in the example below:

R5(config)#int g0/1
R5(config-if)#no lldp transmit'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17907r287973_chk'
  tag severity: 'low'
  tag gid: 'V-216674'
  tag rid: 'SV-216674r531086_rule'
  tag stig_id: 'CISC-RT-000360'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-17905r287974_fix'
  tag 'documentable'
  tag legacy: ['SV-106059', 'V-96921']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
