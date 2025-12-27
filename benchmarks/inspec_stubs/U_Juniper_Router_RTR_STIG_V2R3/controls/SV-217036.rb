control 'SV-217036' do
  title 'The Juniper perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify uRPF or an egress filter has been configured on all internal interfaces to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field.

interfaces {
    ge-0/1/0 {
        description "LAN link";
        unit 0 {
            family inet {
                            rpf-check;

If uRPF or an egress filter to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces in an enclave, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to ensure that an egress filter or uRPF is configured on internal interfaces to restrict the router from accepting any outbound IP packet that contains an illegitimate address in the source field. The example below enables uRPF.

[edit interfaces ge-0/1/0  unit 0 family inet]
set rpf-check'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18265r296976_chk'
  tag severity: 'high'
  tag gid: 'V-217036'
  tag rid: 'SV-217036r604135_rule'
  tag stig_id: 'JUNI-RT-000310'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-18263r296977_fix'
  tag 'documentable'
  tag legacy: ['SV-101067', 'V-90857']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
