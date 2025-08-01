control 'SV-220523' do
  title 'The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. Administrative access to the switch must only be allowed from hosts residing in the management network.

Step 1: Verify that the line vty has an ACL inbound applied as shown in the example below:

line vty 0 1
 access-class MANAGEMENT_NET in
 transport input ssh

Step 2: Verify that the ACL permits only hosts from the management network to access the switch.

ip access-list extended MANAGEMENT_NET 
permit ip x.x.x.0 0.0.0.255 any
deny   ip any any log-input

If the Cisco switch is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to restrict management access to specific IP addresses via SSH as shown in the example below:

SW2(config)#ip access-list standard MANAGEMENT_NET 
SW2(config-std-nacl)#permit x.x.x.0 0.0.0.255 
SW2(config-std-nacl)#exit 
SW2(config)#line vty 0 1
SW2(config-line)#transport input ssh 
SW2(config-line)#access-class MANAGEMENT_NET in 
SW2(config-line)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22238r835135_chk'
  tag severity: 'medium'
  tag gid: 'V-220523'
  tag rid: 'SV-220523r835137_rule'
  tag stig_id: 'CISC-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-22227r835136_fix'
  tag 'documentable'
  tag legacy: ['SV-110501', 'V-101397']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
