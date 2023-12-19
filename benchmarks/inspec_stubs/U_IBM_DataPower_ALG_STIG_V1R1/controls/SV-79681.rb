control 'SV-79681' do
  title 'The DataPower Gateway must enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export controlled information from being transmitted in the clear to the Internet or blocking information marked as classified but is being transported to an unapproved destination.

ALGs enforce approved authorizations by employing security policy and/or rules that restrict information system services, provide packet filtering capability based on header or protocol information and/or message filtering capability based on data content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'Privileged Account User logon to the WebGUI >> Open the service to be modified: From the Control Panel, select the type of service to be edited (e.g., Multi-Protocol Gateway) >> The list of available services will be displayed >> Click the name of the service to be edited.

Verify configuration of the processing policy: Click the “…” button adjacent to the configured Processing Policy (in the case of a Web Service Proxy, click the “Policy” processing policy tab) >> The processing policy is displayed >> Select the rule to be edited by clicking the “Rule Name” >> Double-click on the “Conditional” action.

Confirm the XPath statement for the positive condition (i.e., the condition that, if met, would allow the message to be processed) would result in a “Set Variable” Action being triggered >> Click on the corresponding Set Variable action and confirm that the target URL is correct and that the variable being set is “service/routing-url” >> Click “Done”.

Confirm the XPath statement for the negative condition (i.e., the condition that, if met, would result in the message being blocked) would result in a “Call Processing Rule” Action being triggered >> Click on the corresponding Call Processing Rule action and confirm that the service’s error rule is selected >> Click “Done” >> Click “Done” >> Click “Cancel” >> Click “Cancel”.

If any of the configuration conditions are not met, this is a finding.'
  desc 'fix', 'Privileged Account User logon to the WebGUI >> Open the service to modified: From the Control Panel, select the type of service to be edited (e.g., Multi-Protocol Gateway) >> The list of available services will be displayed >> Click the name of the service to be edited (NOTE: this process is specific to a previously configured service in support of a defined use-case and addressing specific business and technical requirements).

Modify the service’s processing policy: Click the “…” button adjacent to the configured Processing Policy (in the case of a Web Service Proxy, click the “Policy” processing policy tab) >> The processing policy is displayed.
 
Select the rule to be edited by clicking the “Rule Name”.

Configure the Conditional Action: Drag the “Advanced” action to the desired point in the processing rule and double click it >> Select the “Conditional” action and click “Next” >> The “Configure Conditional Action” window is displayed >> A new rule is displayed, consisting of a “Match Condition” and an “Action”.

Paste the XPath statement corresponding to the positive test condition (i.e., the condition that, if met, would allow the message to be processed) into the “Math Condition” field >> In the corresponding “Action”, select “Set Variable” >> Click “Create Action” >> The “Configure Set Variable Action” window is displayed >> In the Variable Name field, paste “service/routing-url” >> In the Viable Assignment field, enter the desired target URL (e.g., (http://somehost.com:port/someURI”) >> Click “Done”. 

In addition to the rule that was just configured, a new rule is displayed, consisting of a “Match Condition” and an “Action”.
 
Paste the XPath statement corresponding to the negative test condition (i.e., the condition that, if met, would result in the message being blocked) into the “Math Condition” field >> In the corresponding “Action”, select “Call Processing Rule” >> Click “Create Action” >> The “Configure Call Processing Rule Action” window is displayed >> From the “Processing Rule” drop-down list, select the name of the processing policy’s configured error rule >> Click “Done” >> Click “Done” >> Click “Apply Policy” >> Click “Close Window” >> Click the “Apply” button >> 
Click “Save Configuration”.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65191'
  tag rid: 'SV-79681r1_rule'
  tag stig_id: 'WSDP-AG-000002'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-71131r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
