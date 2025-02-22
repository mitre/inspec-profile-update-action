control 'SV-79779' do
  title 'The DataPower Gateway providing content filtering must continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network crosses internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'Verify a service, such as a MultiProtocol Gateway, by clicking the icon on the Control Panel.

Click the name of the service in the list >> Set the Name and back end destination for the service.

Under MultiProtocol Gateway Policy, click “...” to inspect the Policy >> Verify the Rule Direction is set to Client to Server.

Double-click the existing Match Action on the rule line and verify it is set to default-accept-service providers.

Double-click the Validate action >> Verify that it is set to a schema file.

Double-click the AAA action to open it >> Click “...” to inspect the AAA Policy >> Follow the wizard steps to review the desired policy. 

When done, click cancel >> Click Cancel or Close window to close the Policy.

If these items have not been configured, this is a finding.'
  desc 'fix', 'Create a new service, such as a MultiProtocol Gateway, by clicking the icon on the Control Panel.

Click Add to create a new service >> Set the Name and back end destination for the service.

Under MultiProtocol Gateway Policy, click “+” to create a new Policy >> Provide a name for the Policy >> Click New Rule >> Set the Rule Direction to Client to Server >> Double-click the existing Match Action on the rule line and select default-accept-service providers >> Drag the Validate action down onto the processing line >> Double-click the action.

Upload the necessary schema definition file to the action >> Click Done.

Drag the AAA action onto the processing line after the Validate action >> Double-click the action to open it >> Click “+” to create a new AAA Policy >> Follow the wizard steps to create the desired policy. 

When done, close the action >> Click Apply to complete the Policy.

Complete the Gateway configuration by clicking Apply.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65289'
  tag rid: 'SV-79779r1_rule'
  tag stig_id: 'WSDP-AG-000111'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-71229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
