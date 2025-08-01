control 'SV-255987' do
  title 'The Arista router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Verify that for the Arista router configuration, access control lists (ACLs) and filters are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. These filters must be applied inbound or outbound on the appropriate external and internal interfaces.

Example:

router# show ip access-lists

Verify IP access list configuration ACLs and filter are configured to allow or deny specific traffic.

!
ip access-list STIG
   10 deny ip 172.16.50.0/30 10.10.100.0/24
   20 permit ip any any
!

Verify the IP access list ACLs are applied to the specific Ethernet interface.

!
router# show ethernet Interface Eth3
!
Interface Ethernet 3
description BGP Link to Gateway Router
no router port
ip address 192.168.1.1/30
   ip access-group STIG in
!

If the Arista router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista routers to enforce ACLs and filters to allow or deny traffic for specific source and destination addresses as well as ports and protocols for controlling information flow.

To configure an IP access list to fulfill this function, enter the following commands, substituting organizational values for the bracketed variables and values.

Step 1:
Ip access-list [name]
[permit/deny] [protocol] [source address] [source port] [destination address] [destination port]
Exit

Step 2:
Apply the filters inbound or outbound on the appropriate external and internal interfaces.

Interface [type] [number]
Ip access-group [name] [direction]

Note: Policy-based routing can also be implemented if needed.'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59663r882301_chk'
  tag severity: 'medium'
  tag gid: 'V-255987'
  tag rid: 'SV-255987r882303_rule'
  tag stig_id: 'ARST-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-59606r882302_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
