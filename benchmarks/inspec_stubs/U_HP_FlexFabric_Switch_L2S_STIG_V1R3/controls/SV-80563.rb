control 'SV-80563' do
  title 'The HP FlexFabric Switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.'
  desc "IP Source Guard provides source IP address filtering on a Layer 2 port to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted Layer 2 access ports. Initially, all IP traffic on the protected port is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that IP Source Guard is enabled on all untrusted access switch ports.

If the HP FlexFabric Switch does not have IP Source Guard enabled on all user-facing or untrusted access switch ports, this is a finding.

[HP]dis ip source binding static
Total entries found: 0
IP Address      MAC Address    Interface                VLAN Type'
  desc 'fix', 'Configure the HP FlexFabric Switch to have IP Source Guard enabled on all user-facing or untrusted access switch ports.

[HP-Ten-GigabitEthernet1/0/10]
[HP-Ten-GigabitEthernet1/0/10]ip verify source ip-address [ mac-address ]
[HP-Ten-GigabitEthernet1/0/10]ip source binding ip-address ip-address [ mac-address mac-address ] [ vlan vlan-id ]'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66073'
  tag rid: 'SV-80563r1_rule'
  tag stig_id: 'HFFS-L2-000015'
  tag gtitle: 'SRG-NET-000362-L2S-000026'
  tag fix_id: 'F-72149r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
