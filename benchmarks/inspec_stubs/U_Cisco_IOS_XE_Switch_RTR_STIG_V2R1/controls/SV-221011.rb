control 'SV-221011' do
  title 'The Cisco perimeter switch must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet, thereby mitigating IP source address spoofing.'
  desc 'check', 'Review the switch configuration to verify uRPF or an egress ACL has been configured on all internal interfaces to restrict the switch from accepting outbound IP packets that contain an illegitimate address in the source address field.

uRPF example:

interface GigabitEthernet0/1
 description downstream link to LAN
 ip address 10.1.25.5 255.255.255.0
 ip verify unicast source reachable-via rx

Egress ACL example:

interface GigabitEthernet0/1
 description downstream link to LAN
 ip address 10.1.25.5 255.255.255.0
 ip access-group EGRESS_FILTER in
…
…
…
ip access-list extended EGRESS_FILTER
 permit udp 10.1.15.0 0.0.0.255 any eq domain
 permit tcp 10.1.15.0 0.0.0.255 any eq ftp
 permit tcp 10.1.15.0 0.0.0.255 any eq ftp-data
 permit tcp 10.1.15.0 0.0.0.255 any eq www
 permit icmp 10.1.15.0 0.0.0.255 any
 permit icmp 10.1.15.0 0.0.0.255 any echo
 deny ip any any

If uRPF or an egress ACL to restrict the switch from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces in an enclave, this is a finding.'
  desc 'fix', 'Configure the switch to ensure that an egress ACL or uRPF is configured on internal interfaces to restrict the switch from accepting any outbound IP packet that contains an illegitimate address in the source field. The example below enables uRPF.

SW1(config)#int g0/1
SW1(config-if)#ip verify unicast source reachable-via rx'
  impact 0.7
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22726r408827_chk'
  tag severity: 'high'
  tag gid: 'V-221011'
  tag rid: 'SV-221011r622190_rule'
  tag stig_id: 'CISC-RT-000310'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-22715r408828_fix'
  tag 'documentable'
  tag legacy: ['SV-110843', 'V-101739']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
