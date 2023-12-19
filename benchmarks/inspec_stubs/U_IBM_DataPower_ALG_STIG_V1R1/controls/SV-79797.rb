control 'SV-79797' do
  title 'The DataPower Gateway must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality."
  desc 'check', 'Review the processing policy for all flows to ensure they contain Validate actions for requests and responses. 

Privileged Account User logon to the WebGUI >> Open the service to modified: From the Control Panel, select the type of service to be edited (e.g., Multi-Protocol Gateway) >> The list of available services will be displayed >> Click the name of the service to be edited.

Verify configuration of the processing policy: Click the “…” button adjacent to the configured Processing Policy (in the case of a Web Service Proxy, click the “Policy” processing policy tab) >> The processing policy is displayed >> Select the rule to be edited by clicking the “Rule Name” >> Ensure there is a Validate action on the rule and that the validate action contains the appropriate schema to check the message against.

If these items have not been configured, this is a finding.'
  desc 'fix', 'Configure the processing policy to use a Validate action. The Validate action will validate the XML or JSON message content against a WSDL or JSON schema.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65307'
  tag rid: 'SV-79797r1_rule'
  tag stig_id: 'WSDP-AG-000122'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-71247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
