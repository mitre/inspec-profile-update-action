control 'SV-75373' do
  title 'The Arista Multilayer Switch must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding.'
  desc 'A compromised host in an enclave can be used by a malicious actor as a platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are collections of compromised computers using malware to attack (usually DDoS) other computers or networks. DDoS attacks frequently leverage IP source address spoofing, in which packets with false source IP addresses send traffic to multiple hosts, which then send return traffic to the hosts with the IP addresses that were forged. This can generate significant, even massive, amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

The router must not accept any outbound IP packets that contain an illegitimate address in the source address field by enabling Unicast Reverse Path Forwarding (uRPF) strict mode or by implementing an egress ACL. Unicast Reverse Path Forwarding (uRPF) provides an IP address spoof protection capability. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet.'
  desc 'check', 'This check is only applicable to external-facing interfaces of a network edge router.

Review the router configuration to verify uRPF or an egress filter to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has been configured on all external interfaces. This is only applicable to perimeter routers.

If uRPF or an egress filter to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces in an enclave, this is a finding.

To verify that uRPF is configured, review the running-config for the interfaces required. The statement "ip-verify unicast source reachable" must be in the configuration. To verify use of an egress filter, verify an IP access list is configured that permits traffic sourced from within the organization address space and that the access list is applied to the egress interface.'
  desc 'fix', 'This check is only applicable to external-facing interfaces of a network edge router.

Configure the router to ensure that an egress filter or uRPF is configured to restrict the router from accepting any outbound IP packet that contains an external IP address in the source field.

Configure uRPF via the "ip-verify unicast source reachable-via [any/strict]" statement from the interface configuration mode.

To apply an egress filter, configure an IP access List:
ip access-list [name]
[ip access list permit/deny statement]
exit

then apply the access list to the external facing interface:

int ethernet [X]
ip access-group [name-of-ACL] out'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60915'
  tag rid: 'SV-75373r1_rule'
  tag stig_id: 'AMLS-L3-000230'
  tag gtitle: 'SRG-NET-000026-RTR-000031'
  tag fix_id: 'F-66627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
