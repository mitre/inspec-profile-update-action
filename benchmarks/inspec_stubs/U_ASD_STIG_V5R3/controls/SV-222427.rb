control 'SV-222427' do
  title 'The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

This is usually established by identifying if there are rulesets, policies or other configurations settings provided by the application which serve to control the flow of information within the system. Control of data flow is established by using labels on data and data subsets, evaluating the destination of the data within or without the system (similar security domain) and referencing a corresponding policy that is used to control the flow of data.

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information within the system in accordance with applicable policy.'
  desc 'check', 'Review the application documentation and interview the application and system administrators.

Review application features and functions to determine if the application is designed to control the flow of information within the system.
Identify:

- rulesets,
- data labels, and
- policies

to determine if the application is designed to control the flow of data within the system.

If the application does not provide data flow control capabilities, the requirement is not applicable.

Access the system as a user with access rights that allow the creation of test data or use of existing test data.

Create a test data set and label the data with a data label provided with or by the application, e.g., Personally Identifiable Information (PII) data.

Review the policy to determine where in the system the PII labeled data is allowed and is not allowed to go.

Using application features and functions, attempt to transmit the labeled data to an area that is prohibited by policy.

Verify the flow control policy was enforced and the data was not transmitted.

If the application does not enforce the approved authorizations for controlling data flow, this is a finding.'
  desc 'fix', 'Configure the application to enforce data flow control in accordance with data flow control policies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24097r493189_chk'
  tag severity: 'medium'
  tag gid: 'V-222427'
  tag rid: 'SV-222427r879533_rule'
  tag stig_id: 'APSC-DV-000480'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-24086r493190_fix'
  tag 'documentable'
  tag legacy: ['V-69333', 'SV-83955']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
