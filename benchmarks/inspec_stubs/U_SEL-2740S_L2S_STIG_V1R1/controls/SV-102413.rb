control 'SV-102413' do
  title 'The SEL-2740S must be configured with ARP flow rules that are statically created with valid IP-to-MAC address bindings.'
  desc 'DAI intercepts Address Resolution Protocol (ARP) requests and verifies that each of these packets has a valid IP-to-MAC address binding before updating the local ARP cache and before forwarding the packet to the appropriate destination. Invalid ARP packets are dropped and logged. DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in the DHCP snooping binding database. If the ARP packet is received on a trusted interface, the switch forwards the packet without any checks. On untrusted interfaces, the switch forwards the packet only if it is valid.'
  desc 'check', 'Review the SEL-2740S configuration to verify that Dynamic Address Resolution Protocol (ARP) flow rules have valid IP-to-MAC address bindings.

If the SEL-2740S Dynamic Address Resolution Protocol (ARP) flow rules are not configured with the valid IP-to-MAC address bindings, this is a finding.'
  desc 'fix', 'To add ARP flow rules on all packet forwarding, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter General Setting values for "Switch", "Enable".  Optional: Enter General Settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
5. Depending on communication protocol behavior, enter appropriate Match Field values for "ARP Opcode" ("Request" or "Reply"), "ARP Source", "ARP Target", "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source", "UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
6. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or Value".
7. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92325'
  tag rid: 'SV-102413r1_rule'
  tag stig_id: 'SELS-SW-000160'
  tag gtitle: 'SRG-NET-000362-L2S-000027'
  tag fix_id: 'F-98563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
