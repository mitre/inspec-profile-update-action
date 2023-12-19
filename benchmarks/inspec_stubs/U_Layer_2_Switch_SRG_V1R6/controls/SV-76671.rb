control 'SV-76671' do
  title 'The layer 2 switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.'
  desc 'In an enterprise network, devices under administrative control are trusted sources. These devices include the switches, routers, and servers in the network. Host ports and unknown DHCP servers are considered untrusted sources. An unknown DHCP server on the network on an untrusted port is called a spurious DHCP server, any device (PC, Wireless Access Point) that is loaded with DHCP server enabled. The DHCP snooping feature determines whether traffic sources are trusted or untrusted. The potential exists for a spurious DHCP server to respond to DHCPDISCOVER messages before the real server has time to respond. DHCP snooping allows switches on the network to trust the port a DHCP server is connected to and not trust the other ports.

The DHCP snooping feature validates DHCP messages received from untrusted sources and filters out invalid messages as well as rate-limits DHCP traffic from trusted and untrusted sources. DHCP snooping feature builds and maintains a binding database, which contains information about untrusted hosts with leased IP addresses, and it utilizes the database to validate subsequent requests from untrusted hosts. Other security features, such as IP Source Guard and Dynamic Address Resolution Protocol (ARP) Inspection (DAI), also use information stored in the DHCP snooping binding database. Hence, it is imperative that the DHCP snooping feature is enabled on all VLANs.'
  desc 'check', 'Review the switch configuration and verify that DHCP snooping is enabled on all user VLANs. 

If the switch does not have DHCP snooping enabled for all user VLANs to validate DHCP messages from untrusted sources, this is a finding.'
  desc 'fix', 'Configure the switch to have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62985r3_chk'
  tag severity: 'medium'
  tag gid: 'V-62181'
  tag rid: 'SV-76671r2_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000025'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68101r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
