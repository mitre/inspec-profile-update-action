control 'SV-217005' do
  title 'The Cisco perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify uRPF or an egress ACL has been configured on all internal interfaces to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field.

uRPF example

interface GigabitEthernet0/0/0/1
 description downstream link to LAN
 ipv4 address 10.1.34.3 255.255.255.0
 ipv4 verify unicast source reachable-via rx

Egress ACL example

ipv4 access-list EGRESS_FILTER
 10 permit udp 10.1.15.0 0.0.0.255 any eq domain
 20 permit tcp 10.1.15.0 0.0.0.255 any eq ftp
 30 permit tcp 10.1.15.0 0.0.0.255 any eq ftp-data
 40 permit tcp 10.1.15.0 0.0.0.255 any eq www
 50 permit icmp 10.1.15.0 0.0.0.255 any
 60 permit icmp 10.1.15.0 0.0.0.255 any echo
 70 deny ipv4 any any
…
…
…
interface GigabitEthernet0/0/0/1
 description downstream link to LAN
 ipv4 address 10.1.34.3 255.255.255.0
 ipv4 access-group EGRESS_FILTER ingress

If uRPF or an egress ACL to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces in an enclave, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to ensure that an egress ACL or uRPF is configured on internal interfaces to restrict the router from accepting any outbound IP packet that contains an  illegitimate address in the source field. The example below enables uRPF.

RP/0/0/CPU0:R3(config)#int g0/0/0/1
RP/0/0/CPU0:R3(config-if)#ipv4 verify unicast source reachable-via rx'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18235r288855_chk'
  tag severity: 'high'
  tag gid: 'V-217005'
  tag rid: 'SV-217005r531087_rule'
  tag stig_id: 'CISC-RT-000310'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-18233r288856_fix'
  tag 'documentable'
  tag legacy: ['SV-105863', 'V-96725']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
