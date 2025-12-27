control 'SV-222428' do
  title 'The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

This is usually established by identifying if there are rulesets, policies or other configurations settings provided by the application which serve to control the flow of information within the system. Control of data flow is established by using labels on data and data subsets, evaluating the destination of the data within or without the system (similar security domain) and referencing a corresponding policy that is used to control the flow of data.

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information within the system in accordance with applicable policy.'
  desc 'check', 'Review the application documentation and interview the application and system administrators.

Identify application features and functions to determine if the application is designed to control the flow of information between interconnected systems.

Identify:

- rulesets,
- data labels
- policies
- systems

to determine if the application is designed to control the flow of data between interconnected systems.

If the application does not provide data flow control capabilities, the requirement is not applicable.

Access the system as a user with access rights allowing the creation of test data or use of existing test data.

Create a test data set and label the data with a data label provided with or by the application (for example, a Personally Identifiable Information (PII) data label).

Review the policy settings to determine where the PII labeled data is allowed and is not allowed.

Using application features and functions, attempt to transmit the labeled data to an interconnected system that is prohibited by policy.

Verify the flow control policy was enforced and the data was not transmitted.

If the application does not enforce the approved authorizations for controlling data flow, this is a finding.'
  desc 'fix', 'Configure the application to enforce data flow control in accordance with data flow control policies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24098r493192_chk'
  tag severity: 'medium'
  tag gid: 'V-222428'
  tag rid: 'SV-222428r508029_rule'
  tag stig_id: 'APSC-DV-000490'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24087r493193_fix'
  tag 'documentable'
  tag legacy: ['V-69335', 'SV-83957']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
