control 'SV-220660' do
  title 'The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.'
  desc "IP Source Guard provides source IP address filtering on a Layer 2 port to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted Layer 2 access ports. Initially, all IP traffic on the protected port is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', 'NOTE: For VLANs managed via 802.1x, this check is N/A.

Review the switch configuration to verify that IP Source Guard is enabled on all user-facing or untrusted access switch ports as shown in the example below:

interface GigabitEthernet0/0
 ip verify source
!
interface GigabitEthernet0/1
 ip verify source
…
…
…
interface GigabitEthernet0/9 
 ip verify source

Note: The IP Source Guard feature depends on the entries in the DHCP snooping database or static IP-MAC-VLAN configuration commands to verify IP-to-MAC address bindings.

If the switch does not have IP Source Guard enabled on all untrusted access switch ports, this is a finding.'
  desc 'fix', 'Configure the switch to have IP Source Guard enabled on all user-facing or untrusted access switch ports.

SW2(config)#int range g0/0 - 9
SW2(config-if-range)#ip verify source'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22375r863268_chk'
  tag severity: 'medium'
  tag gid: 'V-220660'
  tag rid: 'SV-220660r863269_rule'
  tag stig_id: 'CISC-L2-000140'
  tag gtitle: 'SRG-NET-000362-L2S-000026'
  tag fix_id: 'F-22364r507529_fix'
  tag 'documentable'
  tag legacy: ['SV-110291', 'V-101187']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
