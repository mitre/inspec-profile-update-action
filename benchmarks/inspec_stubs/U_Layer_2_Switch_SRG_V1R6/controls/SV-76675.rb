control 'SV-76675' do
  title 'The layer 2 switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the switch configuration to verify that Dynamic Address Resolution Protocol (ARP) Inspection (DAI) feature is enabled on all user VLANs.

If DAI is not enabled on all user VLANs, this is a finding.'
  desc 'fix', 'Configure the switch to have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62989r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62185'
  tag rid: 'SV-76675r1_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000027'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
