control 'SV-215812' do
  title 'The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. 

Step 1: Verify that the line vty has an ACL inbound applied as shown in the example below.

line vty 0 4
 access-class MANAGEMENT_NET in
 transport input ssh

Step 2: Verify that the ACL permits only hosts from the management network to access the router.

ip access-list extended MANAGEMENT_NET 
permit ip x.x.x.0 0.0.0.255 any
deny   ip any any log-input


If the Cisco router is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Configure the Cisco router to restrict management access to specific IP addresses via SSH as shown in the example below.

SW2(config)#ip access-list standard MANAGEMENT_NET 
SW2(config-std-nacl)#permit x.x.x.0 0.0.0.255 
SW2(config-std-nacl)#exit 
SW2(config)#line vty 0 4 
SW2(config-line)#transport input ssh 
SW2(config-line)#access-class MANAGEMENT_NET in 
SW2(config-line)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17051r539419_chk'
  tag severity: 'medium'
  tag gid: 'V-215812'
  tag rid: 'SV-215812r539421_rule'
  tag stig_id: 'CISC-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-17049r539420_fix'
  tag 'documentable'
  tag legacy: ['V-96205', 'SV-105343']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
