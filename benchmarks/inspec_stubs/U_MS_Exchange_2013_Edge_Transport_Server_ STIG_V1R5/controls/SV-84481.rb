control 'SV-84481' do
  title 'Exchange Message size restrictions must be controlled on Receive connectors.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability. 

This setting enables the administrator to control the maximum message size on Receive connectors. Using connectors to control size limits may necessitate applying message size limitations in multiple places, with the potential of introducing conflicts and impediments in the mail flow. Changing this setting at the connector overrides the global one. Therefore, if operational needs require it, the connector value may be set lower than the global value with the rationale documented in the EDSP.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the global maximum message receive size. 

Open the Exchange Management Shell and enter the following command:

Identify Internet-facing connectors. 

Get-ReceiveConnector | Select Name, Identity, MaxMessageSize 

If the value of MaxMessageSize is not the same as the global value, this is a finding.

or

If MaxMessageSize is set to a numeric value different from the global value and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxMessageSize <'MaxReceiveSize'>

Note: The <IdentityName> and <MaxReceiveSize> values must be in quotes.

or 

The value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70327r1_chk'
  tag severity: 'low'
  tag gid: 'V-69859'
  tag rid: 'SV-84481r1_rule'
  tag stig_id: 'EX13-EG-000160'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-76089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
