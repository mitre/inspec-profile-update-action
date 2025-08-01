control 'SV-255973' do
  title 'The Arista MLS layer 2 switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.'
  desc 'In an enterprise network, devices under administrative control are trusted sources. These devices include the switches, routers, and servers in the network. Host ports and unknown DHCP servers are considered untrusted sources. An unknown DHCP server on the network on an untrusted port is called a spurious DHCP server, any device (PC, Wireless Access Point) that is loaded with DHCP server enabled. The DHCP snooping feature determines whether traffic sources are trusted or untrusted. The potential exists for a spurious DHCP server to respond to DHCPDISCOVER messages before the real server has time to respond. DHCP snooping allows switches on the network to trust the port a DHCP server is connected to and not trust the other ports.

The DHCP snooping feature validates DHCP messages received from untrusted sources and filters out invalid messages as well as rate-limits DHCP traffic from trusted and untrusted sources. DHCP snooping feature builds and maintains a binding database, which contains information about untrusted hosts with leased IP addresses, and it utilizes the database to validate subsequent requests from untrusted hosts. Other security features, such as IP Source Guard and Dynamic Address Resolution Protocol (ARP) Inspection (DAI), also use information stored in the DHCP snooping binding database. Hence, it is imperative that the DHCP snooping feature is enabled on all user VLANs.'
  desc 'check', 'Review the Arista MLS switch configuration and verify that DHCP snooping is enabled on all user VLANs.

Verify the Arista MLS has the DHCP Snooping feature enabled globally by executing "show ip dhcp snooping".

switch(config)# show ip dhcp snooping
DHCP Snooping is enabled
DHCP Snooping is operational
DHCP Snooping is configured on following VLANs:
 650
DHCP Snooping is operational on following VLANs:
 650

If the Arista MLS switch does not have DHCP snooping enabled for all user VLANs to validate DHCP messages from untrusted sources, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to have DHCP snooping enabled globally and for all user VLANs to validate DHCP messages from untrusted sources.

Step 1: Configure DHCP Snooping globally by using the following command:

switch(config)# ip dhcp snooping

Step 2: Configure DHCP Snooping to enable the insertion of option-82 in DHCP request packets. By default, option-82 is not enabled and without this, DHCP Snooping is not operational.

switch(config)#ip dhcp snooping information option

Step 3: Configure the Arista MLS switch to enable IP DHCP Snooping on the corresponding VLANs. By default, DHCP Snooping will not be enabled on any VLAN.

switch(config)#ip dhcp snooping vlan <vlan-id>

Step 4: Configure the following command to set the circuit-id information that will be sent in option-82. By default, Interface name and VLAN ID are sent. Remote circuit-id will always be the MAC address of the relay agent.

switch# ip dhcp snooping information option circuit-id type 2 format
  Hostname and interface name
  Interface name and VLAN ID'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59649r882259_chk'
  tag severity: 'medium'
  tag gid: 'V-255973'
  tag rid: 'SV-255973r882261_rule'
  tag stig_id: 'ARST-L2-000090'
  tag gtitle: 'SRG-NET-000362-L2S-000025'
  tag fix_id: 'F-59592r882260_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
