control 'SV-80565' do
  title 'The HP FlexFabric Switch must have Dynamic ARP Inspection (DAI) enabled on all user VLANs.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that Dynamic ARP Inspection (DAI) feature is enabled on all user VLANs.

If DAI is not enabled on all user VLANs, this is a finding.

[HP]display arp detection
 ARP detection is enabled in the following VLANs:
 2

[HP]display arp detection statistics interface Ten-GigabitEthernet 1/0/11
State: U-Untrusted  T-Trusted
ARP packets dropped by ARP inspect checking:
Interface(State)            IP        Src-MAC   Dst-MAC   Inspect
XGE1/0/11(T)                0         0         0         0
[HP]'
  desc 'fix', 'Configure the HP FlexFabric Switch to have Dynamic ARP Inspection (DAI) enabled on all user VLANs.

[HP-vlan2]arp detection enable

[HP-Ten-GigabitEthernet1/0/11]arp detection trust'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66075'
  tag rid: 'SV-80565r1_rule'
  tag stig_id: 'HFFS-L2-000016'
  tag gtitle: 'SRG-NET-000362-L2S-000027'
  tag fix_id: 'F-72151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
