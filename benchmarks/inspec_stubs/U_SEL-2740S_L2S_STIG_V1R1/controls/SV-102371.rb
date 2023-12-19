control 'SV-102371' do
  title 'The SEL-2740S must be configured to forward only frames from allowed network-connected endpoint devices.'
  desc 'By only allowing frames to be forwarded from known end-points mitigates risks associated with broadcast, unknown unicast, and multicast traffic storms.'
  desc 'check', 'To ensure only allowed traffic is being forwarded through the device, check the flow rules for source and destination information on each connected device and port.

If there are any flow rules that are not restrictive, this is a finding.'
  desc 'fix', 'Ensure only authentic allowed traffic by creating flow rules to restrict protocol, source, and destination of information.

For adding an SEL-2740S Flow Rule to forward traffic, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter General settings values for "Switch", "Enable".  Optional: Enter General Settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
5. Depending on communication protocol behavior, enter appropriate Match Field values for "ARP Opcode" ("Request" or "Reply"), "ARP Source", "ARP Target", "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source", "UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
6. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or Value".
7. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92283'
  tag rid: 'SV-102371r1_rule'
  tag stig_id: 'SELS-SW-000310'
  tag gtitle: 'SRG-NET-000512-L2S-000031'
  tag fix_id: 'F-98523r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
