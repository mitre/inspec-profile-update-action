control 'SV-255974' do
  title 'The Arista MLS layer 2 switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.'
  desc "IP Source Guard (IPSG) provides source IP address filtering on a layer 2 port to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted Layer 2 access ports. Initially, all IP traffic on the protected port is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', 'Review the Arista MLS switch configuration to verify that IPSG is enabled on all user-facing or untrusted access switch ports.

Step 1: The Arista MLS switch command verifies the IPSG configuration and operational states.

switch(config)#show ip verify source

Interface       Operational State
--------------- ------------------------
Ethernet1       IP source guard enabled
Ethernet2       IP source guard disabled

Step 2: The following command displays all VLANs configured in no IP verify source VLAN:

switch(config)#show ip verify source vlan

IPSG disabled on VLANS: 1-2
VLAN            Operational State
--------------- ------------------------
1               IP source guard disabled
2               Error: vlan classification failed

If the Arista MLS switch does not have IP Source Guard enabled on all untrusted access switch ports, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to have IPSG enabled on all user-facing or untrusted access switch ports.

Step 1: The Arista MLS IPSG feature must be configured by applying filters to inbound IP packets based on their source MAC and IP addresses. The following example commands exclude VLAN IDs 1 through 3 from IPSG filtering. When enabled on a trunk port, IPSG filters the inbound IP packets on all allowed VLANs. IP packets received on VLANs 4 through 10 on Ethernet 36 will be filtered by IPSG, while those received on VLANs 1 through 3 are permitted.

switch(config)#no ip verify source vlan 1-3
switch(config)#interface ethernet 36
switch(config-if-Et36)#switchport mode trunk
switch(config-if-Et36)#switchport trunk allowed vlan 1-10
switch(config-if-Et36)#ip verify source
switch(config-if-Et36)#

Step 2: By using the Arista MLS switch command, the switch binds the source IP-MAC binding entries to IP address 10.1.1.1, MAC address 0000.aaaa.1111, VLAN ID 4094, and Ethernet interface 36.

switch(config)#ip source binding 10.1.1.1 0000.aaaa.1111 vlan 4094 interface ethernet 36
switch(config)#'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59650r882262_chk'
  tag severity: 'medium'
  tag gid: 'V-255974'
  tag rid: 'SV-255974r882264_rule'
  tag stig_id: 'ARST-L2-000100'
  tag gtitle: 'SRG-NET-000362-L2S-000026'
  tag fix_id: 'F-59593r882263_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
