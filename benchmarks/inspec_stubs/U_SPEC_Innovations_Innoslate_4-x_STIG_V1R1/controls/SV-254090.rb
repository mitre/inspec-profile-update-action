control 'SV-254090' do
  title 'Innoslate must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data. 

Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information within the system in accordance with applicable policy.'
  desc 'check', '1. Sign in as owner of project.
2. Enter Schema Editor.
3. Click "Workflow".
4. Verify permissions are applied to the workflow classes specified. If not, this is a finding.'
  desc 'fix', '1. Sign in as owner of project.
2. Enter Schema Editor.
3. Click "Workflow".
4. Verify permissions are applied to the workflow classes specified.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57575r845244_chk'
  tag severity: 'medium'
  tag gid: 'V-254090'
  tag rid: 'SV-254090r845246_rule'
  tag stig_id: 'SPEC-IN-000085'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-57526r845245_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
