control 'SV-216735' do
  title 'The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. For example, the configuration below will allow only printer traffic into subnet 10.1.23.0/24 and SQL traffic into subnet 10.1.24.0/24. ICMP is allowed for troubleshooting and OSPF is the routing protocol used within the network.

interface GigabitEthernet0/0/0/0
 description link to core
 ipv4 address 10.1.12.2 255.255.255.0
 ipv4 access-group FILTER_SERVER_TRAFFIC ingress
…
…
…
ipv4 access-list FILTER_SERVER_TRAFFIC
 10 permit tcp any 10.1.23.0 0.0.0.255 eq lpd
 20 permit tcp any 10.1.23.0 0.0.0.255 eq 631
 30 permit tcp any 10.1.23.0 0.0.0.255 eq 9100
 40 permit tcp any 10.1.24.0 0.0.0.255 eq 1433
 50 permit tcp any 10.1.24.0 0.0.0.255 eq 1434
 60 permit tcp any 10.1.24.0 0.0.0.255 eq 4022
 70 permit icmp any any
 80 permit ospf any any
 90 deny ipv4 any any

If the router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure ACLs to allow or deny traffic for specific source and destination addresses as well as ports and protocols between various subnets as required. The commands used below were used to create the configuration as shown in the check content.

RP/0/0/CPU0:R2(config)#ipv4 access-list FILTER_SERVER_TRAFFIC
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.23.0 0.0.0.255 eq lpd 
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.23.0 0.0.0.255 eq 631
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.23.0 0.0.0.255 eq 9100
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.24.0 0.0.0.255 eq 1433  
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.24.0 0.0.0.255 eq 1434  
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any 10.1.24.0 0.0.0.255 eq 4022
RP/0/0/CPU0:R2(config-ipv4-acl)#permit icmp any any
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ospf any any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny   ip any any
RP/0/0/CPU0:R2(config-ipv4-acl)#
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#int g0/0/0/0
RP/0/0/CPU0:R2(config-if)#ipv4 access-group FILTER_SERVER_TRAFFIC'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17967r288603_chk'
  tag severity: 'medium'
  tag gid: 'V-216735'
  tag rid: 'SV-216735r531087_rule'
  tag stig_id: 'CISC-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-17965r288604_fix'
  tag 'documentable'
  tag legacy: ['V-96677', 'SV-105815']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
