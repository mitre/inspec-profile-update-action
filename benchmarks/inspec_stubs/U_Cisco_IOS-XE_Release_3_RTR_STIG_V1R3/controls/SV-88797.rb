control 'SV-88797' do
  title 'The Cisco IOS XE router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding.'
  desc 'A compromised host in an enclave can be used by a malicious actor as a platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack (usually DDoS) other computers or networks. DDoS attacks frequently leverage IP source address spoofing, in which packets with false source IP addresses send traffic to multiple hosts, which then send return traffic to the hosts with the IP addresses that were forged. This can generate significant, even massive, amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

The router must not accept any outbound IP packets that contain an illegitimate address in the source address field by enabling Unicast Reverse Path Forwarding (uRPF) strict mode or by implementing an egress ACL. Unicast Reverse Path Forwarding (uRPF) provides an IP address spoof protection capability. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet.'
  desc 'check', 'Review the Cisco IOS XE router configuration to validate uRPF or an ACL on an inbound direction has been configured on all internal interfaces as shown in the example below:

uRPF Example:

interface FastEthernet 0/0
description downstream link to enclave LAN
ip address x.x.x.x 255.255.255.0
ip verify unicast source reachable-via rx 102

access-list 102 deny ip any any log

ACL Example:

interface FastEthernet 0/0
description downstream link to our network
ip address 199.36.90.1 255.255.255.0
ip access-group 102 in
...
access-list 102 permit tcp any any established
access-list 102 permit tcp [internal network] [wildcard mask] any eq ftp-data
access-list 102 permit tcp [internal network] [wildcard mask] any eq ftp
access-list 102 permit tcp [internal network] [wildcard mask] any eq http
access-list 102 permit . . .
access-list 102 deny any

If the Cisco IOS XE router has not been configured with uRPF strict mode or an ACL inbound on all internal interfaces, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router with uRPF strict mode or an ACL inbound on all internal interfaces as shown in the examples below:

uRPF Example:

interface FastEthernet 0/0
description downstream link to enclave LAN
ip address x.x.x.x 255.255.255.0
ip verify unicast source reachable-via rx 102

access-list 102 deny ip any any log

ACL Example:

interface FastEthernet 0/0
description downstream link to our network
ip address 199.36.90.1 255.255.255.0
ip access-group 102 in
...
access-list 102 permit tcp any any established
access-list 102 permit tcp [internal network] [wildcard mask] any eq ftp-data
access-list 102 permit tcp [internal network] [wildcard mask] any eq ftp
access-list 102 permit tcp [internal network] [wildcard mask] any eq http
access-list 102 permit . . .
access-list 102 deny any'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74209r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74123'
  tag rid: 'SV-88797r2_rule'
  tag stig_id: 'CISR-RT-000014'
  tag gtitle: 'SRG-NET-000026-RTR-000031'
  tag fix_id: 'F-80665r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
