control 'SV-216675' do
  title 'The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.'
  desc 'CDP is a Cisco proprietary neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. CDP is media-and-protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing CDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify if CDP is enabled globally as shown below:

cdp run

By default, CDP is not enabled globally or on any interface. If CDP is enabled globally, proceed to step 2.

Step 2: Verify CDP is not enabled on any external interface as shown in the example below:

interface GigabitEthernet2
 ip address z.1.24.4 255.255.255.252
 …
 …
 …
cdp enable

If CDP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Disable CDP on all external interfaces via no cdp enable command or disable CDP globally via no cdp run command.'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17908r287976_chk'
  tag severity: 'low'
  tag gid: 'V-216675'
  tag rid: 'SV-216675r531086_rule'
  tag stig_id: 'CISC-RT-000370'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-17906r287977_fix'
  tag 'documentable'
  tag legacy: ['SV-106061', 'V-96923']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
