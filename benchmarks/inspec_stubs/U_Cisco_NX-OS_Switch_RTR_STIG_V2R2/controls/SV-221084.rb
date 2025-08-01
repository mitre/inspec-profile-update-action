control 'SV-221084' do
  title 'The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Switches automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the switch configuration to determine if it is compliant with this requirement. The ip unreachables command must not be found on any interface as shown in the example below:

interface Ethernet2/7
 no switchport
 ip address x.22.4.2/30
 ip unreachables

If ICMP unreachable notifications are sent from any external interfaces, this is a finding.'
  desc 'fix', 'Disable ip unreachables on all external interfaces as shown below:

SW1(config)# int e2/7
SW1(config-if)# no ip unreachables
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22799r409741_chk'
  tag severity: 'medium'
  tag gid: 'V-221084'
  tag rid: 'SV-221084r856637_rule'
  tag stig_id: 'CISC-RT-000170'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag fix_id: 'F-22788r409742_fix'
  tag 'documentable'
  tag legacy: ['SV-110987', 'V-101883']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
