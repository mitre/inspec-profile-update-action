control 'SV-80643' do
  title 'The HP FlexFabric Switch must enforce approved authorizations for controlling the flow of management information within the HP FlexFabric Switch based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the HP FlexFabric Switch may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the HP FlexFabric Switch or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if ACLs were configured for controlling the flow of management information within the HP FlexFabric Switch based on information flow control policies:

[HP] display current-configuration 

acl number 3000
 description ACL to block traffic with invalid address
 rule 0 permit icmp source 10.0.0.0 0.255.255.255
 rule 1 deny ip source 172.16.0.0 0.15.255.255
 rule 2 deny ip source 192.168.0.0 0.0.255.255
 rule 3 deny ip source 169.254.0.0 0.0.255.255
 rule 6 deny ip source 127.0.0.0 0.255.255.255

If ACLs are not configured for controlling the flow of management information within the HP FlexFabric Switch based on information flow control policies , this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch for controlling the flow of management information within the HP FlexFabric Switch based on information flow control policies. Below is an example for an ACL configuration:

[HP] acl number 3000
[HP-acl-adv-3000] description ACL to block traffic with invalid address
[HP-acl-adv-3000] rule 0 permit icmp source 10.0.0.0 0.255.255.255
[HP-acl-adv-3000] rule 1 deny ip source 172.16.0.0 0.15.255.255
[HP-acl-adv-3000] rule 2 deny ip source 192.168.0.0 0.0.255.255
[HP-acl-adv-3000]  rule 3 deny ip source 169.254.0.0 0.0.255.255
[HP-acl-adv-3000]  rule 6 deny ip source 127.0.0.0 0.255.255.255

[HP] interface Vlan-interface 192
[HP-Vlan-interface192] packet-filter 3000 inbound'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66153'
  tag rid: 'SV-80643r1_rule'
  tag stig_id: 'HFFS-ND-000014'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-72229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
