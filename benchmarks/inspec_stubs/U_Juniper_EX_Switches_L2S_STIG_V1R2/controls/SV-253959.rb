control 'SV-253959' do
  title 'The Juniper EX switch must be configured to enable DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.'
  desc 'In an enterprise network, devices under administrative control are trusted sources. These devices include the switches, routers, and servers in the network. Host interfaces and unknown DHCP servers are considered untrusted sources. An unknown DHCP server on the network on an untrusted interface is called a spurious DHCP server, any device (PC, Wireless Access Point) that is loaded with DHCP server enabled. The DHCP snooping feature determines whether traffic sources are trusted or untrusted. The potential exists for a spurious DHCP server to respond to DHCPDISCOVER messages before the real server has time to respond. DHCP snooping allows switches on the network to trust the interface a DHCP server is connected to and not trust the other interfaces.

The DHCP snooping feature validates DHCP messages received from untrusted sources and filters out invalid messages as well as rate-limits DHCP traffic from trusted and untrusted sources. The DHCP snooping feature builds and maintains a binding database, which contains information about untrusted hosts with leased IP addresses, and it utilizes the database to validate subsequent requests from untrusted hosts. Other security features, such as IP Source Guard and Dynamic Address Resolution Protocol (ARP) Inspection (DAI), also use information stored in the DHCP snooping binding database. Hence, it is imperative that the DHCP snooping feature is enabled on all user-facing or untrusted VLANs.'
  desc 'check', 'Review the switch configuration and verify that DHCP snooping is enabled on all user-facing or untrusted VLANs. 

DHCP snooping is enabled if dhcp-security is configured for any VLAN, and is automatically enabled whenever any other VLAN port security feature is configured (e.g., IP Source Guard or Dynamic ARP Inspection). 

Devices like printers, servers, and VoIP phones are under administrative control and connected to controlled access interfaces (802.1x, Static MAC Bypass, or MAC RADIUS), making them trusted sources in non-user-facing VLANs.

Verify DHCP snooping on user-facing or untrusted VLANs.

[edit vlans]
<untrusted VLAN name> {
    vlan-id <VLAN ID>;
    forwarding-options {
        dhcp-security;
    }
}

If the switch does not have DHCP snooping enabled for all user-facing or untrusted VLANs to validate DHCP messages from untrusted sources, this is a finding.'
  desc 'fix', 'Configure the switch to have DHCP snooping for all user-facing or untrusted VLANs to validate DHCP messages from untrusted sources.

set vlans <untrusted VLAN name> vlan-id <untrusted VLAN ID>
set vlans <untrusted VLAN name> forwarding-options dhcp-security'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57411r843908_chk'
  tag severity: 'medium'
  tag gid: 'V-253959'
  tag rid: 'SV-253959r843910_rule'
  tag stig_id: 'JUEX-L2-000120'
  tag gtitle: 'SRG-NET-000362-L2S-000025'
  tag fix_id: 'F-57362r843909_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
