control 'SV-220661' do
  title 'The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the switch configuration to verify that Dynamic Address Resolution Protocol (ARP) Inspection (DAI) feature is enabled on all user VLANs. 

hostname SW2
…
…
…
ip arp inspection vlan 2,4-8,11

Note: DAI depends on the entries in the DHCP snooping binding database to verify IP-to-MAC address bindings in incoming ARP requests and ARP responses.

If DAI is not enabled on all user VLANs, this is a finding.'
  desc 'fix', 'Configure the switch to have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs as shown in the example below:

SW2(config)#ip arp inspection vlan 2,4-8,11'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22376r929002_chk'
  tag severity: 'medium'
  tag gid: 'V-220661'
  tag rid: 'SV-220661r929003_rule'
  tag stig_id: 'CISC-L2-000150'
  tag gtitle: 'SRG-NET-000362-L2S-000027'
  tag fix_id: 'F-22365r507532_fix'
  tag 'documentable'
  tag legacy: ['SV-110293', 'V-101189']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
