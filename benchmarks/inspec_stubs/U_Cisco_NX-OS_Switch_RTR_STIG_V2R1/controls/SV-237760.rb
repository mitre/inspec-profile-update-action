control 'SV-237760' do
  title 'The Cisco perimeter switch must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'Review the switch configuration to verify that Router Advertisements are suppressed on all external IPv6-enabled interfaces as shown in the example below.

interface Ethernet1/1
  no switchport
  ipv6 address 2001::1:24:3/64
  ipv6 nd suppress-ra
  no shutdown 


If the switch is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the switch to suppress Router Advertisements on all external IPv6-enabled interfaces as shown in the example below.

SW1(config)#  interface e1/1
SW1(config-if-range)#  ipv6 nd suppress-ra
SW1(config-if-range)#  end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-40975r648793_chk'
  tag severity: 'medium'
  tag gid: 'V-237760'
  tag rid: 'SV-237760r648795_rule'
  tag stig_id: 'CISC-RT-000391'
  tag gtitle: 'SRG-NET-000512-RTR-000014'
  tag fix_id: 'F-40937r648794_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
