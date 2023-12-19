control 'SV-253961' do
  title 'The Juniper EX switch must be configured to enable Dynamic Address Resolution Protocol (ARP) Inspection (DAI) on all user VLANs.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the switch configuration to verify that Dynamic Address Resolution Protocol (ARP) Inspection (DAI) feature is enabled on all user VLANs. Configuring DAI automatically enables DHCP snooping.

Devices like printers, servers, and VoIP phones are under enterprise control and connected to controlled access interfaces (802.1x, Static MAC Bypass, or MAC RADIUS), making them trusted sources in non-user-facing VLANs.

Verify DAI on user-facing or untrusted VLANs.
[edit vlans]
<untrusted VLAN name> {
    vlan-id <VLAN ID>;
    forwarding-options {
        dhcp-security {
            arp-inspection;
        }
    }
}
Note: DAI depends upon DHCP snooping or static MAC address bindings.

If DAI is not enabled on all user VLANs, this is a finding.'
  desc 'fix', 'Configure the switch to have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.

set vlans <untrusted VLAN name> vlan-id <VLAN ID>
set vlans <untrusted VLAN name> forwarding-options dhcp-security arp-inspection'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57413r843914_chk'
  tag severity: 'medium'
  tag gid: 'V-253961'
  tag rid: 'SV-253961r843916_rule'
  tag stig_id: 'JUEX-L2-000140'
  tag gtitle: 'SRG-NET-000362-L2S-000027'
  tag fix_id: 'F-57364r843915_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
