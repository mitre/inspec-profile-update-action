control 'SV-221085' do
  title 'The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Switches automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the switch configuration to verify that the no ip redirects command has been configured on all external interfaces as shown in the example below:

interface Ethernet2/7
 no switchport
 ip address x.22.4.2/30
 no ip redirects

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces as shown in the example below:

SW1(config)# int e2/7
SW1(config-if)# no ip redirects'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22800r409744_chk'
  tag severity: 'medium'
  tag gid: 'V-221085'
  tag rid: 'SV-221085r622190_rule'
  tag stig_id: 'CISC-RT-000190'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-22789r409745_fix'
  tag 'documentable'
  tag legacy: ['SV-110989', 'V-101885']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
