control 'SV-80611' do
  title 'The HP FlexFabric Switch must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding.'
  desc 'A compromised host in an enclave can be used by a malicious actor as a platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack (usually DDoS) other computers or networks. DDoS attacks frequently leverage IP source address spoofing, in which packets with false source IP addresses send traffic to multiple hosts, which then send return traffic to the hosts with the IP addresses that were forged. This can generate significant, even massive, amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

The router must not accept any outbound IP packets that contain an illegitimate address in the source address field by enabling Unicast Reverse Path Forwarding (uRPF) strict mode or by implementing an egress ACL. Unicast Reverse Path Forwarding (uRPF) provides an IP address spoof protection capability. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet.'
  desc 'check', 'Display the switch configuration to verify that either the command ip urpf strict has been configured or an egress filter has been configured on all internal-facing interfaces to drop all outbound packets with an illegitimate source address.
If uRPF or an egress filter to restrict the switch from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal-facing interfaces, this is a finding.'
  desc 'fix', 'Configure the global command  ip urpf strict on the switch.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66121'
  tag rid: 'SV-80611r1_rule'
  tag stig_id: 'HFFS-RT-000017'
  tag gtitle: 'SRG-NET-000026-RTR-000031'
  tag fix_id: 'F-72197r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
