control 'SV-216585' do
  title 'The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.'
  desc 'CDP is a Cisco proprietary neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. CDP is media- and protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing CDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify CDP is not enabled globally via the command no cdp run

By default CDP is enabled globally; hence, the command cdp run will not be shown in the configuration. If CDP is enabled, proceed to step 2.

Step 2: Verify CDP is not enabled on any external interface as shown in the example below.

interface GigabitEthernet0/1
 ip address x.1.23.2 255.255.255.252
 no cdp enable

Note: By default CDP is enabled on all interfaces if CDP is enabled globally.

If CDP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Disable CDP on all external interfaces via no cdp enable command or disable CDP globally via no cdp run command.'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17820r287133_chk'
  tag severity: 'low'
  tag gid: 'V-216585'
  tag rid: 'SV-216585r531085_rule'
  tag stig_id: 'CISC-RT-000370'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-17816r287134_fix'
  tag 'documentable'
  tag legacy: ['SV-105709', 'V-96571']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
