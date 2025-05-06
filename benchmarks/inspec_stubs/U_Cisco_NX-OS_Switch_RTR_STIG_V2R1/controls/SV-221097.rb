control 'SV-221097' do
  title 'The Cisco perimeter switch must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.'
  desc 'CDP is a Cisco proprietary neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. CDP is media-and-protocol-independent as it runs over layer 2; therefore, two network nodes that support different layer 3 protocols can still learn about each other. Allowing CDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'Step 1: Verify CDP is not enabled globally via the command no cdp enable

By default CDP is enabled globally; hence, the command cdp enable will not be shown in the configuration. If CDP is enabled, proceed to Step 2.

Step 2: Verify CDP is not enabled on any external interface as shown in the example below:

interface Ethernet2/2
 description link to DISN
 no switchport
 no cdp enable

Note: By default CDP is enabled on all interfaces if CDP is enabled globally.

If CDP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable CDP on all external interfaces via no cdp enable interface command or disable CDP globally via no cdp enable command.'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22812r409780_chk'
  tag severity: 'low'
  tag gid: 'V-221097'
  tag rid: 'SV-221097r622190_rule'
  tag stig_id: 'CISC-RT-000370'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-22801r409781_fix'
  tag 'documentable'
  tag legacy: ['SV-111013', 'V-101909']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
