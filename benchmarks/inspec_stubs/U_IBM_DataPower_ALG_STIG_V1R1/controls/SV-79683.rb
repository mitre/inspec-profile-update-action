control 'SV-79683' do
  title 'The DataPower Gateway must restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the ALG when used as a gateway or boundary device which allows traffic flow between interconnected networks of differing security policies.

The ALG is installed and configured such that it restricts or blocks information flows based on guidance in the PPSM regarding restrictions for boundary crossing for ports, protocols and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The ALG must be configured with policy filters (e.g., security policy, rules, and/or signatures) that restrict or block information system services; provide a packet-filtering capability based on header information; and/or perform message-filtering based on message content. The policy filters used depends upon the type of application gateway (e.g., web, email, or TLS).'
  desc 'check', 'Privileged Account User logon to the WebGUI >> Open the service to be modified: From the Control Panel, select the type of service to be edited (e.g., Multi-Protocol Gateway) >> The list of available services will be displayed >> Click the name of the service to be edited.

Verify configuration of the processing policy: Click the “…” button adjacent to the configured Processing Policy (in the case of a Web Service Proxy, click the “Policy” processing policy tab) >> The processing policy is displayed >> Select the rule to be edited by clicking the “Rule Name” >> Double-click on the “Conditional” action.

Confirm the XPath statement for the positive condition (i.e., the condition that, if met, would allow the message to be processed) would result in a “Set Variable” Action being triggered >> Click on the corresponding Set Variable action and confirm that the target URL is correct and that the variable being set is “service/routing-url” >> Click “Done”.

Confirm the XPath statement for the negative condition (i.e., the condition that, if met, would result in the message being blocked) would result in a “Call Processing Rule” Action being triggered >> Click on the corresponding Call Processing Rule action and confirm that the service’s error rule is selected >> Click “Done” >> Click “Done” >> Click “Cancel” >> Click “Cancel”.

If any of the configuration conditions are not met, this is a finding.'
  desc 'fix', 'Privileged Account User logon to the WebGUI >> Open the service to modified: From the Control Panel, select the type of service to be edited (e.g., Multi-Protocol Gateway) >> The list of available services will be displayed >> Click the name of the service to be edited (NOTE: This process is specific to a previously configured service in support of a defined use-case and addressing specific business and technical requirements).

Modify the service’s processing policy: Click the “…” button adjacent to the configured Processing Policy (in the case of a Web Service Proxy, click the “Policy” processing policy tab) >> The processing policy is displayed. 

Select the rule to be edited by clicking the “Rule Name”.

Configure the Conditional Action: Drag the “Advanced” action to the desired point in the processing rule and double click it >> Select the “Conditional” action and click “Next” >> The “Configure Conditional Action” window is displayed >> A new rule is displayed, consisting of a “Match Condition” and an “Action”.

Paste the XPath statement corresponding to the positive test condition (i.e., the condition that, if met, would allow the message to be processed) into the “Math Condition” field >> In the corresponding “Action”, select “Set Variable” >> Click “Create Action” >> The “Configure Set Variable Action” window is displayed >> In the Variable Name field, past “service/routing-url” >> In the Viable Assignment field, enter the desired target URL (e.g., (http://somehost.com:port/someURI”) >> Click “Done”. 

In addition to the rule that was just configured, a new rule is displayed, consisting of a “Match Condition” and an “Action”. 

Paste the XPath statement corresponding to the negative test condition (i.e., the condition that, if met, would result in the message being blocked) into the “Math Condition” field >> In the corresponding “Action”, select “Call Processing Rule” >> Click “Create Action” >> The “Configure Call Processing Rule Action” window is displayed >> From the “Processing Rule” drop-down list, select the name of the processing policy’s configured error rule >> Click “Done” >> Click “Done” >> Click “Apply Policy” >> Click “Close Window” >> Click the “Apply” button >> Click “Save Configuration”.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65193'
  tag rid: 'SV-79683r1_rule'
  tag stig_id: 'WSDP-AG-000003'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-71133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
