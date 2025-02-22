control 'SV-255975' do
  title 'The Arista MLS layer 2 switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the Arista MLS switch configuration to verify that Dynamic Address Resolution Protocol (ARP) Inspection (DAI) feature is enabled on all user VLANs.

Verify ARP inspection for user VLANs by the following command:

sh ip arp inspection vlan

VLAN 2200
------------
Configuration: Enabled
Operation State: Active

If static ARP inspection is not enabled on all user VLANs, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to have static Address Resolution Protocol (ARP) Inspection to be enabled on all user VLANs.

By default, Arista MLS switch static ARP Inspection is disabled on all VLANs. Static ARP inspection can be enabled on all specific user VLANs by using the following command:

switch(config)#ip arp inspection vlan <vlan-list>'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59651r882265_chk'
  tag severity: 'medium'
  tag gid: 'V-255975'
  tag rid: 'SV-255975r882267_rule'
  tag stig_id: 'ARST-L2-000110'
  tag gtitle: 'SRG-NET-000362-L2S-000027'
  tag fix_id: 'F-59594r882266_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
