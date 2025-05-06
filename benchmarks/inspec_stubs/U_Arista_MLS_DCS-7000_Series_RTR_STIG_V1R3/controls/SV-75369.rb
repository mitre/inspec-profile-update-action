control 'SV-75369' do
  title 'The Arista Multilayer Switch must enforce information flow control using explicit security attributes (for example, IP addresses, port numbers, protocol, Autonomous System, or interface) on information, source, and destination objects.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Restrictions can be enforced based on source and destination IP addresses as well as the ports and services being requested. This requirement should enforce the deny-by-default policy whereby only the known and accepted traffic will be allowed outbound and inbound.'
  desc 'check', 'If explicit security attributes (for example, IP addresses, port numbers, protocol, Autonomous System, or interface) are not used to enforce information flow control, this is a finding.

Review the configuration of any access control list on the switch to determine if explicit attributes are being utilized. The ACL must include explicit attributes such as ip addresses, port numbers, protocols, etc.

Note that the Arista MLS includes a deny-by-default statement that is not displayed in the CLI. This statement exists at the end of every ACL.'
  desc 'fix', 'Configure the router to enforce flow control using explicit security attributes (for example, IP addresses, port numbers, protocol, Autonomous System, or interface) on information, source, and destination objects as a basis for flow control decisions.

To enforce flow control using explicit security attributes, configure access control lists as per organization-defined requirements, to include statements such as:

ip access-list [Name}
deny [protocol] [source address] [source port] [destination address] [destination port] [dscp filter] [ttl filter]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60911'
  tag rid: 'SV-75369r2_rule'
  tag stig_id: 'AMLS-L3-000210'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-66623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002190']
  tag nist: ['CM-6 b', 'AC-4 (1)']
end
