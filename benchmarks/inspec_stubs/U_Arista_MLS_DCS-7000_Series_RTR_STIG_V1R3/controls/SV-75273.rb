control 'SV-75273' do
  title 'The Arista Multilayer Switch must enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Verify each router enforces approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

This requirement may be met through the use of IP access control lists. To verify IP access lists are configured, execute the "show ip access-lists summary" command, and check that the list is configured and is active on applicable interfaces. To verify the lists control the flow of information in accordance with organizational policy, enter the "show ip access-list [name]" command, and review the associated permit and deny statements.

If the router does not enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy, this is a finding.'
  desc 'fix', 'Configure the router to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

To use an IP access list to fulfill this function, enter the following commands, substituting organizational values for the bracketed variables.

ip access-list [name]
[permit/deny] [protocol] [source address] [source port] [destination address] [destination port] 
exit

interface [type] [number]
ip access-group [name] [direction]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60817'
  tag rid: 'SV-75273r1_rule'
  tag stig_id: 'AMLS-L3-000100'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-66503r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
