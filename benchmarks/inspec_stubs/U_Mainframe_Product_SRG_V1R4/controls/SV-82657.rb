control 'SV-82657' do
  title 'The Mainframe Product must enforce approved authorizations for controlling the flow of information within the system based on site security plan information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information within the system in accordance with applicable policy.'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product enforces approved authorizations for controlling the flow of information within the system with applicable access control policies. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to enforce approved authorizations for controlling the flow of information within the system with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68167'
  tag rid: 'SV-82657r1_rule'
  tag stig_id: 'SRG-APP-000038-MFP-000067'
  tag gtitle: 'SRG-APP-000038-MFP-000067'
  tag fix_id: 'F-74283r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
