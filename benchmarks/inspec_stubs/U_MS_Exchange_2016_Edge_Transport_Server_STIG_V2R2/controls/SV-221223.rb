control 'SV-221223' do
  title 'Exchange message size restrictions must be controlled on Send connectors.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability. 

This setting enables the administrator to control the maximum message size on a Send connector. Using connectors to control size limits may necessitate applying message size limitations in multiple places, with the potential of introducing conflicts and impediments in the mail flow. Changing this setting at the connector overrides the global one. Therefore, if operational needs require it, the connector value may be set lower than the global value with the rationale documented in the EDSP.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the maximum message send size.

Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, MaxMessageSize

For each send connector, if the value of "MaxMessageSize" is not the same as the global value, this is a finding.

or

If "MaxMessageSize" is set to a numeric value different from the maximum message send size value documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP to reflect the maximum message send size.

Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -MaxMessageSize <MaxSendSize>

Note: The <IdentityName> value must be in single quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each send connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22938r411795_chk'
  tag severity: 'low'
  tag gid: 'V-221223'
  tag rid: 'SV-221223r612603_rule'
  tag stig_id: 'EX16-ED-000240'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22927r411796_fix'
  tag 'documentable'
  tag legacy: ['SV-95237', 'V-80527']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
