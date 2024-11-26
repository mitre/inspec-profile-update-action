control 'SV-102363' do
  title 'The SEL-2740S  must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via identification of connecting hosts can assist in preventing a malicious user from connecting an unauthorized PC to a switch port to inject or receive data from the network without detection.'
  desc 'check', 'Review SEL-2740S flow rules to ensure they contain the proper match criteria (MAC, IP, Port, SRC, DST, etc.) for the connected hosts restricting all other access to the network. 

If the SEL-2740S is configured with flows with wildcard or unnecessary packet forwarding rules, this is a finding.'
  desc 'fix', 'For adding an SEL-2740S Flow Rule to forward traffic, do the following:
1. Log in to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter General Setting values for "Switch", "Enable".  Optional: Enter General Settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
5. Depending on communication protocol behavior, enter appropriate Match Field values for "ARP Opcode" ("Request" or "Reply"), "ARP Source", "ARP Target", "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source", "UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
6. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or Value".
7. Click "Submit".
8. Repeat for every switch necessary.'
  impact 0.7
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91561r1_chk'
  tag severity: 'high'
  tag gid: 'V-92263'
  tag rid: 'SV-102363r1_rule'
  tag stig_id: 'SELS-SW-000020'
  tag gtitle: 'SRG-NET-000148-L2S-000015'
  tag fix_id: 'F-98503r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
