control 'SV-255948' do
  title 'The Arista network device must enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data.

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Verify the Arista network device is configured with access control lists to control the flow of management information.

Step 1: Verify SSH has an inbound ACL applied as shown in the example below.

sh run | sec management ssh
 ip access-group MGMT_NETWORK in

Step 2: Verify the ACL permits only hosts from the management network to access the device.

sh run | sec access-list MGMT_NETWORK
 ip access-list MGMT_NETWORK
   10 permit ip 10.1.12.0/24 any
   20 deny ip any any log

If the Arista network device is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Step 1: Configure an ACL for SSH access using the following commands:

switch(config)#ip access-list MGMT_NETWORK
switch(config-acl-MGMT_NETWORK)#10 permit ip 10.1.12.0/24 any
switch(config-acl-MGMT_NETWORK)#20 deny ip any any log
switch(config-acl-MGMT_NETWORK)#exit

Step 2: Apply the ACL to management ssh.

switch(config)#management ssh 
switch(config-mgmt-ssh)#ip access-group MGMT_NETWORK in
switch(config-mgmt-ssh)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59624r882184_chk'
  tag severity: 'medium'
  tag gid: 'V-255948'
  tag rid: 'SV-255948r882186_rule'
  tag stig_id: 'ARST-ND-000110'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-59567r882185_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
