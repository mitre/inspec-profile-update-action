control 'SV-223013' do
  title 'The firewall must be configured to restrict it from accepting outbound packets that contain an illegitimate address in the source address field via an egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'Review the firewall configuration to verify uRPF or an egress filter has been configured on all internal interfaces to restrict the firewall from accepting outbound packets that contain an illegitimate address in the source address field.

If uRPF or an egress ACL to restrict the firewall from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces, this is a finding.'
  desc 'fix', 'Configure the firewall with an egress filter or uRPF on all internal interfaces to restrict the firewall from accepting any outbound packet that contains an  illegitimate address in the source field.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-24686r457855_chk'
  tag severity: 'medium'
  tag gid: 'V-223013'
  tag rid: 'SV-223013r604133_rule'
  tag stig_id: 'SRG-NET-000364-FW-000042'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-24674r457856_fix'
  tag 'documentable'
  tag legacy: ['SV-110211', 'V-101107']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
