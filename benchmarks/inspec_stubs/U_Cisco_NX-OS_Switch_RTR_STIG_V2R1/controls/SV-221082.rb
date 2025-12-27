control 'SV-221082' do
  title 'The Cisco switch must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled on all external interfaces as shown in the example below:

interface Ethernet2/7
 no switchport
 ip address x.22.4.2/30
 no ip arp gratuitous request

Note: Gratuitous ARP is enabled on all interfaces by default.

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable Gratuitous ARP as shown in the example below:

SW1(config)# int e2/7
SW1(config-if)# no ip arp gratuitous request
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22797r409735_chk'
  tag severity: 'medium'
  tag gid: 'V-221082'
  tag rid: 'SV-221082r622190_rule'
  tag stig_id: 'CISC-RT-000150'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-22786r409736_fix'
  tag 'documentable'
  tag legacy: ['SV-110983', 'V-101879']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
