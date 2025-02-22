control 'SV-102401' do
  title 'The SEL-2740S must be configured to permit the allowed and necessary ports, functions, protocols, and services.'
  desc 'A compromised switch introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each switch is to enable only the capabilities required for operation.'
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
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92313'
  tag rid: 'SV-102401r1_rule'
  tag stig_id: 'SELS-SW-000010'
  tag gtitle: 'SRG-NET-000131-L2S-000014'
  tag fix_id: 'F-98551r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
