control 'SV-246929' do
  title 'ONTAP must enforce approved authorizations for controlling the flow of management information.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data.

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Use "security login show" to see all configured users and their roles. Use "security login role show" to see specific commands allowed for each role.

If ONTAP does not enforce approved authorizations for controlling the flow of management information, this is a finding.'
  desc 'fix', 'Configure roles with "security login role create -role <name>" to create new roles, and "security login create -user-or-group-name <user_name> -role <name>" to assign the role to a specific user or group.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50361r769117_chk'
  tag severity: 'medium'
  tag gid: 'V-246929'
  tag rid: 'SV-246929r769119_rule'
  tag stig_id: 'NAOT-AC-000008'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-50315r769118_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
