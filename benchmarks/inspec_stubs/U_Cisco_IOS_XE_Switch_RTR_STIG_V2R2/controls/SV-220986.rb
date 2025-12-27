control 'SV-220986' do
  title 'The Cisco switch must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, switches, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet-filtering capability based on header information, or provide a message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Review the switch configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. For example, the configuration below will allow only printer traffic into subnet 10.1.12.0/24 and SQL traffic into subnet 10.1.13.0/24. ICMP is allowed for troubleshooting and OSPF is the routing protocol used within the network.

interface GigabitEthernet0/1
 no switchport
 ip address 10.2.1.1 255.255.255.252
 ip access-group FILTER_SERVER_TRAFFIC in 
…
…
…
ip access-list extended FILTER_SERVER_TRAFFIC
 permit tcp any 10.1.12.0 0.0.0.255 eq lpd 631 9100
 permit tcp any 10.1.13.0 0.0.0.255 eq 1433 1434 4022
 permit icmp any any
 permit ospf any any
 deny ip any any

Alternate: Inter-VLAN routing

interface Vlan12
 ip address 10.1.12.1 255.255.255.0
 ip access-group FILTER_PRINTER_VLAN out
!
interface Vlan13
 ip address 10.1.13.1 255.255.255.0
 ip access-group FILTER_SQL_VLAN out
…
…
…
ip access-list extended FILTER_PRINTER_VLAN
 permit tcp any any eq lpd 631 9100
 permit icmp any any
 deny ip any any
ip access-list extended FILTER_SQL_VLAN
 permit tcp any any eq 1433 1434 4022
 permit icmp any any
 deny ip any any

If the switch is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'Configure ACLs to allow or deny traffic for specific source and destination addresses as well as ports and protocols between various subnets as required. The commands used below were used to create the configuration as shown in the check content.

SW1(config)#ip access-list extended FILTER_SERVER_TRAFFIC
SW1(config-ext-nacl)#permit tcp any 10.1.12.0 0.0.0.255 eq 515 631 9100
SW1(config-ext-nacl)#permit tcp any 10.1.13.0 0.0.0.255 eq 1433 1434 4022
SW1(config-ext-nacl)#permit icmp any any
SW1(config-ext-nacl)#permit ospf any any
SW1(config-ext-nacl)#deny ip any any
SW1(config-ext-nacl)#exit
SW1(config)#interface g0/1
SW1(config-if)#ip access-group FILTER_SERVER_TRAFFIC in
SW1(config-if)#end

Alternate: Inter-VLAN routing

SW1(config)#ip access-list extended FILTER_PRINTER_VLAN
SW1(config-ext-nacl)#permit tcp any any eq lpd 631 9100
SW1(config-ext-nacl)#permit icmp any any
SW1(config-ext-nacl)#deny ip any any
SW1(config-ext-nacl)#exit
SW1(config)#ip access-list extended FILTER_SQL_VLAN
SW1(config-ext-nacl)#permit tcp any any eq 1433 1434 4022
SW1(config-ext-nacl)#permit icmp any any
SW1(config-ext-nacl)#deny ip any any
SW1(config-ext-nacl)#exit
SW1(config)#interface vlan 12
SW1(config-if)#ip access-group FILTER_PRINTER_VLAN out
SW1(config-if)#exit
SW1(config)#interface vlan 13
SW1(config-if)#ip access-group FILTER_SQL_VLAN out
SW1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22701r408752_chk'
  tag severity: 'medium'
  tag gid: 'V-220986'
  tag rid: 'SV-220986r622190_rule'
  tag stig_id: 'CISC-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-22690r408753_fix'
  tag 'documentable'
  tag legacy: ['SV-110793', 'V-101689']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
