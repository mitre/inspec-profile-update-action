control 'SV-220479' do
  title 'The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. 

Step 1: Verify that the line vty has an ACL inbound applied as shown in the example below:

line vty
 access-class MGMT_NET in

Step 2: Verify that the ACL permits only hosts from the management network to access the switch.

ip access-list MGMT_NET
 10 permit ip 10.1.48.0/24 any 
 20 deny ip any any log


NX-OS v8 and later example
Step 1: Verify that an ACL has been applied to the management interface inbound as shown in the example below: 

interface mgmt0
ip access-group MGMT_NET in 

Step 2: Verify that the ACL permits only hosts from the management network to access the switch. 

ip access-list MGMT_NET 
10 permit ip 10.1.48.0/24 any  
20 deny ip any any log 


If the Cisco switch is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to restrict management access to specific IP addresses as shown in the example below:

SW1(config)# ip access-list MGMT_NET 
SW1(config-acl)# permit ip 10.1.48.0/24 any
SW1(config-acl)# deny ip any any log
SW1(config-acl)# exit
SW1(config)# line vty
SW1(config-line)# access-class MGMT_NET in
SW1(config-acl)# end


NX-OS v8 and later example

SW1(config)# ip access-list MGMT_NET  
SW1(config-acl)# permit ip 10.1.48.0/24 any 
SW1(config-acl)# deny ip any any log 
SW1(config-acl)# exit 
SW1(config)# interface mgmt0
SW1(config-if)#  ip access-group MGMT_NET in 
SW1(config-acl)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22194r648767_chk'
  tag severity: 'medium'
  tag gid: 'V-220479'
  tag rid: 'SV-220479r879533_rule'
  tag stig_id: 'CISC-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-22183r648768_fix'
  tag 'documentable'
  tag legacy: ['SV-110605', 'V-101501']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
