control 'SV-102411' do
  title 'SEL-2740S flow rules must include the host IP addresses that are bound to designated SEL-2740S ports for ensuring trusted host access.'
  desc "IP Source Guard provides source IP address filtering on a Layer 2 port to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted Layer 2 access ports. Initially, all IP traffic on the protected port is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', "Review the SEL-2740S flow rules to ensure all include IP addresses assigned to given hosts and are bound to the SEL-2740S ports.

If the SEL-2740S flow rules are not configured with hosts' IP addresses for packets ingressing or egressing the ports, this is a finding."
  desc 'fix', %q(To add IP Host addressed flow rules on all packet forwarding, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter General Setting values for "Switch", "Enable".  Optional: Enter General Settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
5. Depending on communication protocol behavior, enter appropriate Match Field values for "ARP Opcode" ("Request" or "Reply"), "ARP Source", "ARP Target', "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source', 'UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
6. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or Value".
7. Click "Submit".)
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92323'
  tag rid: 'SV-102411r1_rule'
  tag stig_id: 'SELS-SW-000150'
  tag gtitle: 'SRG-NET-000362-L2S-000026'
  tag fix_id: 'F-98561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
