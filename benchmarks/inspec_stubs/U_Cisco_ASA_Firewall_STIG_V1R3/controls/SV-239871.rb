control 'SV-239871' do
  title 'The Cisco ASA must be configured to restrict it from accepting outbound packets that contain an illegitimate address in the source address field via an egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. Denial-of-Service attacks frequently leverage IP source address spoofing to send packets to multiple hosts that, in turn, will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet, thereby mitigating IP source address spoofing.'
  desc 'check', 'Review the firewall configuration to verify uRPF or an egress filter has been configured on all internal interfaces to restrict the firewall from accepting outbound packets that contain an illegitimate address in the source address field.

URF Example:

ip verify reverse-path interface INSIDE

ACL Example:

Step 1: Verify that an ACL has been applied inbound on the inside interfaces as shown in the example below.

access-group INSIDE_IN in interface INSIDE

Step 2: Verify that the ACL only allows packets from legitimate internal source addresses.

object-group network LAN_SUBNETS
 network-object 10.1.10.0 255.255.255.0
 network-object 10.1.12.0 255.255.255.0
 network-object 10.1.13.0 255.255.255.0
 network-object 10.1.22.0 255.255.255.0
…
…
…
access-list INSIDE_IN extended permit ip object-group LAN_SUBNETS any 
access-list INSIDE_IN extended deny ip any any

Note: Traffic that is permitted must be in compliance with the PPSM.

If uRPF or an egress ACL to restrict the firewall from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces, this is a finding.'
  desc 'fix', 'Configure the firewall with an egress filter or uRPF on all internal interfaces to restrict the firewall from accepting any outbound packet that contains an illegitimate address in the source field.

URF Example:

ip verify reverse-path interface INSIDE

ACL Example:

Step 1: Configure an object group containing the allowed subnets as shown in the example below.

ASA(config)# object-group network LAN_SUBNETS
ASA(config-network-object-group)# network-object 10.1.10.0 255.255.255.0
ASA(config-network-object-group)# network-object 10.1.12.0 255.255.255.0
ASA(config-network-object-group)# network-object 10.1.13.0 255.255.255.0
ASA(config-network-object-group)# network-object 10.1.22.0 255.255.255.0
ASA(config-network-object-group)# exit

Step 2: Configure the ACL.

ASA(config)# access-list INSIDE_IN permit ip object-group LAN_SUBNETS any
ASA(config)# access-list INSIDE_IN deny ip any any     

Note: Traffic that is permitted must be in compliance with the PPSM.   

Step 3: Apply the ACL inbound on the inside interface.

ASA(config)# access-group INSIDE_IN in interface INSIDE'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43104r665897_chk'
  tag severity: 'medium'
  tag gid: 'V-239871'
  tag rid: 'SV-239871r665899_rule'
  tag stig_id: 'CASA-FW-000290'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag fix_id: 'F-43063r665898_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
