control 'SV-230044' do
  title 'The Cisco perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that Router Advertisements are suppressed on all external IPv6-enabled interfaces as shown in the example below.

interface gigabitethernet1/0
 ipv6 address 2001::1:0:22/64
 ipv6 nd ra suppress

If the router is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the router to suppress Router Advertisements on all external IPv6-enabled interfaces as shown in the example below.
R1(config)#int g1/0
R1(config-if)#ipv6 nd ra suppress
R1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-32354r533003_chk'
  tag severity: 'medium'
  tag gid: 'V-230044'
  tag rid: 'SV-230044r533005_rule'
  tag stig_id: 'CISC-RT-000391'
  tag gtitle: 'SRG-NET-000512-RTR-000014'
  tag fix_id: 'F-32331r533004_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
