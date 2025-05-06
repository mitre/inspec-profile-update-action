control 'SV-239901' do
  title 'The Cisco ASA must be configured to enforce approved authorizations for controlling the flow of management information within the Cisco ASA based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the Cisco ASA configuration to verify that management access is restricted to specific IP address space as shown in the example below. 

ssh x.x.x.0 255.255.255.0 INSIDE

If the Cisco ASA is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to restrict management access to specific IP addresses via SSH as shown in the example below.

ASA(config)# ssh x.x.x.0 255.255.255.0 INSIDE 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43134r666064_chk'
  tag severity: 'medium'
  tag gid: 'V-239901'
  tag rid: 'SV-239901r879533_rule'
  tag stig_id: 'CASA-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-43093r666065_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
