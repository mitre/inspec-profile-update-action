control 'SV-221071' do
  title 'The Cisco switch must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, switches, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet-filtering capability based on header information, or provide a message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Review the switch configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. For example, the configuration below will allow only printer traffic into subnet 10.1.12.0/24 and SQL traffic into subnet 10.1.13.0/24. ICMP is allowed for troubleshooting and OSPF is the routing protocol used within the network.

interface Ethernet2/3
 no switchport
 ip access-group FILTER_SERVER_TRAFFIC in
 ip address 10.1.23.2/24
 no shutdown 
…
…
…
ip access-list FILTER_SERVER_TRAFFIC
 10 permit tcp any 10.1.12.0/24 eq lpd 
 20 permit tcp any 10.1.12.0/24 eq 631 
 30 permit tcp any 10.1.12.0/24 eq 9100 
 40 permit tcp any 10.1.13.0/24 eq 1433 
 50 permit tcp any 10.1.13.0/24 eq 1434 
 60 permit tcp any 10.1.13.0/24 eq 4022 
 70 permit icmp any any 
 80 permit ospf any any 
 90 deny ip any any

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
ip access-list FILTER_PRINTER_VLAN
 10 permit tcp any any eq lpd 
 20 permit tcp any any eq 631 
 30 permit tcp any any eq 9100 
 40 permit icmp any any 
 50 deny ip any any
ip access-list FILTER_SQL_VLAN
 10 permit tcp any any eq 1433 
 20 permit tcp any any eq 1434 
 30 permit tcp any any eq 4033 
 40 permit icmp any any 
 50 deny ip any any

If the switch is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'Configure ACLs to allow or deny traffic for specific source and destination addresses as well as ports and protocols between various subnets as required. The commands used below were used to create the configuration as shown in the check content.

SW1(config)# ip access-list FILTER_SERVER_TRAFFIC
SW1(config-acl)# permit tcp any 10.1.12.0 0.0.0.255 eq lpd 
SW1(config-acl)# permit tcp any 10.1.12.0 0.0.0.255 eq 631
SW1(config-acl)# permit tcp any 10.1.12.0 0.0.0.255 eq 9100
SW1(config-acl)# permit tcp any 10.1.13.0 0.0.0.255 eq 1433
SW1(config-acl)# permit tcp any 10.1.13.0 0.0.0.255 eq 1434
SW1(config-acl)# permit tcp any 10.1.13.0 0.0.0.255 eq 4022
SW1(config-acl)# permit icmp any any
SW1(config-acl)# permit ospf any any
SW1(config-acl)# deny ip any any
SW1(config-acl)# exit
SW1(config)# int e2/3
SW1(config-if)# ip access-group FILTER_SERVER_TRAFFIC in
SW1(config-if)# end

Alternate: Inter-VLAN routing

SW1(config)# ip access-list FILTER_PRINTER_VLAN
SW1(config-acl)# permit tcp any any eq lpd 
SW1(config-acl)# permit tcp any any eq 631
SW1(config-acl)# permit tcp any any eq 9100
SW1(config-acl)# permit icmp any any
SW1(config-acl)# deny ip any any
SW1(config-acl)# exit
SW1(config)# ip access-list FILTER_SQL_VLAN
SW1(config-acl)# permit tcp any any eq 1433
SW1(config-acl)# permit tcp any any eq 1434
SW1(config-acl)# permit tcp any any eq 4033
SW1(config-acl)# permit icmp any any
SW1(config-acl)# deny ip any any
SW1(config-acl)# exit
SW1(config)# int vlan 12
SW1(config-if)# ip access-group FILTER_PRINTER_VLAN out
SW1(config-if)# exit
SW1(config)# int vlan 13
SW1(config-if)# ip access-group FILTER_SQL_VLAN out
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22786r409702_chk'
  tag severity: 'medium'
  tag gid: 'V-221071'
  tag rid: 'SV-221071r622190_rule'
  tag stig_id: 'CISC-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-22775r409703_fix'
  tag 'documentable'
  tag legacy: ['SV-110961', 'V-101857']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
