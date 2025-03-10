control 'SV-220450' do
  title 'The Cisco perimeter switch must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.'
  desc 'CDP is a Cisco proprietary neighbor discovery protocol used to advertise device capabilities, configuration information, and device identity. CDP is media-and-protocol-independent as it runs over Layer 2; therefore, two network nodes that support different Layer 3 protocols can still learn about each other. Allowing CDP messages to reach external network nodes provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'Step 1: Verify if CDP is enabled globally as shown below: 

cdp run 

By default, CDP is not enabled globally or on any interface. If CDP is enabled globally, proceed to Step 2. 

Step 2: Verify CDP is not enabled on any external interface as shown in the example below: 

interface GigabitEthernet2 
 ip address z.1.24.4 255.255.255.252 
… 
 … 
 … 
cdp enable 

If CDP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable CDP on all external interfaces via no cdp enable command or disable CDP globally via no cdp run command.'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22165r508429_chk'
  tag severity: 'low'
  tag gid: 'V-220450'
  tag rid: 'SV-220450r622190_rule'
  tag stig_id: 'CISC-RT-000370'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-22154r508430_fix'
  tag 'documentable'
  tag legacy: ['SV-110747', 'V-101643']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
