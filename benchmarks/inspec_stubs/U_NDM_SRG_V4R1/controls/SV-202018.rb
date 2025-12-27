control 'SV-202018' do
  title 'The network device must enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the network device configuration to determine if it enforces approved authorizations for controlling the flow of management information within the network device based on information flow control policies. If it does not enforce these approved authorizations, this is a finding.'
  desc 'fix', 'Configure the network device to enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2144r381584_chk'
  tag severity: 'medium'
  tag gid: 'V-202018'
  tag rid: 'SV-202018r395568_rule'
  tag stig_id: 'SRG-APP-000038-NDM-000213'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-2145r381585_fix'
  tag 'documentable'
  tag legacy: ['SV-69299', 'V-55053']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
