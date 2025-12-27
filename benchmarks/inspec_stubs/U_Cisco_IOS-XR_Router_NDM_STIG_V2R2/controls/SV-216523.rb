control 'SV-216523' do
  title 'The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. 

Step 1: Verify that the line vty has an ACL inbound applied as shown in the example below.

line default
 access-class ingress MANAGEMENT_NET
 transport input ssh
!
vty-pool default 0 4

Step 2: Verify that the ACL permits only hosts from the management network to access the router.

ipv4 access-list MANAGEMENT_NET 
10 permit ipv4 10.1.1.0 255.255.255.0 any
20 deny ipv4 any any log-input

If the Cisco router is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Configure the Cisco router to restrict management access to specific IP addresses via SSH as shown in the example below.

RP/0/0/CPU0:ios(config)#ipv4 access-list MANAGEMENT_NET
RP/0/0/CPU0:ios(config-ipv4-acl)#permit ipv4 10.1.1.0 255.255.255.0 any
RP/0/0/CPU0:ios(config-ipv4-acl)#deny ipv4 any any log-input 
RP/0/0/CPU0:ios(config-ipv4-acl)#exit
RP/0/0/CPU0:R3(config)#vty default 0 4 
RP/0/0/CPU0:R3(config)#line default 
RP/0/0/CPU0:R3(config-line)#transport input ssh 
RP/0/0/CPU0:R3(config-line)#access-class MANAGEMENT_NET in 
RP/0/0/CPU0:R3(config-line)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17758r569665_chk'
  tag severity: 'medium'
  tag gid: 'V-216523'
  tag rid: 'SV-216523r539428_rule'
  tag stig_id: 'CISC-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-17755r569623_fix'
  tag 'documentable'
  tag legacy: ['SV-105517', 'V-96379']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
