control 'SV-256026' do
  title 'The Arista perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the router configuration to verify uRPF or an egress filter has been configured on all internal interfaces to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field.

To verify restrict uRPF is configured on the interface to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field, execute the command "sh run int eth YY".

interface Ethernet3/17/1
ip address 172.16.43.3/24
ip verify unicast source reachable-via rx

If uRPF or an egress filter to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista router to ensure an egress filter or uRPF is configured to restrict the router from accepting any outbound IP packet that contains an external IP address in the source field.

LEAF-1A(config)#interface Ethernet3/17/1
LEAF-1A(config)#ip address 172.16.43.3/24
LEAF-1A(config)#ip verify unicast source reachable-via rx'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59702r882418_chk'
  tag severity: 'high'
  tag gid: 'V-256026'
  tag rid: 'SV-256026r882420_rule'
  tag stig_id: 'ARST-RT-000450'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-59645r882419_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
