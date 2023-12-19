control 'SV-228382' do
  title 'Exchange Message size restrictions must be controlled on Receive connectors.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability. 

This setting enables the administrator to control the maximum message size on receive connectors. Using connectors to control size limits may necessitate applying message size limitations in multiple places, with the potential of introducing conflicts and impediments in the mail flow. Changing this setting at the connector overrides the global one. Therefore, if operational needs require it, the connector value may be set lower than the global value with the rationale documented in the Email Domain Security Plan (EDSP).'
  desc 'check', 'Review the EDSP or document that contains this information.

Determine the global maximum message receive size and whether signoff with risk acceptance is documented for the Receive connector to have a different value.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxMessageSize 

Identify Internet-facing connectors. 

For each Receive connector, if the value of "MaxMessageSize" is not the same as the global value, this is a finding.

or

If "MaxMessageSize" is set to a numeric value different from the global value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP to specify the global maximum message receive size and, if operationally necessary, to document signoff with risk acceptance for the Receive connector to have a different value, or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxMessageSize <'MaxReceiveSize'>

Note: The <IdentityName> and <MaxReceiveSize> values must be in single quotes.

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each Receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30615r496942_chk'
  tag severity: 'low'
  tag gid: 'V-228382'
  tag rid: 'SV-228382r879651_rule'
  tag stig_id: 'EX16-MB-000350'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30600r496943_fix'
  tag 'documentable'
  tag legacy: ['SV-95389', 'V-80679']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
