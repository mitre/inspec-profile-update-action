control 'SV-102365' do
  title 'The SEL-2740S must be configured to mitigate the risk of ARP cache poisoning attacks.'
  desc 'The SEL-2740S must deter ARP cache poisoning attacks and configure the specific ARP flows that are only necessary to the control system network.'
  desc 'check', 'Review SEL-2740S ARP flow rules between hosts and ensure they are necessary for the additional flow rules that exist for communications between hosts.

Note: Necessary flows are all ARPs between valid and authorized hosts that should be allowed to talk to each other and the physical path those circuits are allowed to talk.

If the SEL-2740S is configured with wildcard packet forwarding flows that are not for Security Information and Event Manager (SIEM) or unnecessary rules, this is a finding.'
  desc 'fix', 'Configure point-to-point ARP flow rules between every device that must communicate.

To add ARP flow rules on all packet forwarding, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter General setting values for "Switch", "Enable".  Optional: Enter General Settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
5. Depending on communication protocol behavior, enter appropriate Match Field values for "ARP Opcode" ("Request" or "Reply"), "ARP Source", "ARP Target", "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source", "UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
6. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or Value".
7. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91575r2_chk'
  tag severity: 'medium'
  tag gid: 'V-92277'
  tag rid: 'SV-102365r1_rule'
  tag stig_id: 'SELS-SW-000280'
  tag gtitle: 'SRG-NET-000512-L2S-000028'
  tag fix_id: 'F-98517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
