control 'SV-88645' do
  title 'The Cisco IOS XE router must enforce approved authorizations for controlling the flow of management information within the router based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Verify that the Cisco IOS XE router has ACLs configured and apply to the appropriate interfaces to control the flow of traffic.

The configuration should look similar to the example below:

interface GigabitEthernet 0/0/1
description  MGMT  link
ip address x.x.x.x 255.255.255.0
ip access-group Authorized_Sources_ACL in
...

Extended IP access list Authorized_Source_ACL
    10 permit 22 host 2.2.2.2 host 3.3.3.3 log
    20 deny ip any any log

If ACLs are not configured, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router with ACLs, applied to the appropriate interfaces to control the flow of management information.

The configuration should look similar to the example below:

interface GigabitEthernet 0/0/1
description  MGMT  link
ip address x.x.x.x 255.255.255.0
ip access-group Authorized_Sources_ACL in
...

Extended IP access list Authorized_Source_ACL
    10 permit 22 host 2.2.2.2 host 3.3.3.3 log
    20 deny ip any any log'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74053r4_chk'
  tag severity: 'medium'
  tag gid: 'V-73971'
  tag rid: 'SV-88645r2_rule'
  tag stig_id: 'CISR-ND-000014'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-80511r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
