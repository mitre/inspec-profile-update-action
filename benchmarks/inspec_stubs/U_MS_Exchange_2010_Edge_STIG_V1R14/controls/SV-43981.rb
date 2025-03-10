control 'SV-43981' do
  title 'Message size restrictions must be controlled on Receive connectors.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability. 

This setting enables the administrator to control the maximum message size on receive connectors. Using connectors to control size limits may necessitate the need to apply message size limitations in multiple places, with the potential of introducing conflicts and impediments in the mail flow. Changing this setting at the connector overrides the global one. Therefore, if operational needs require it, the connector value may be set lower than that of the global value with the rationale and documented in the EDSP.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the global maximum message receive size and if signoff with risk acceptance is documented for the receive connector to have a different value.

Open the Exchange Management Shell and enter the following command:
Get-ReceiveConnector | Select Name, Identity, MaxMessageSize 

or

Get-TransportConfig | Select Identity, MaxReceiveSize 

Identify Internet-facing connectors on the Edge Transport server. 

If 'MaxMessageSize' is set to a numeric value different from the global value, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of ‘MaxMessageSize' is not the same as the global value, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -MaxMessageSize <MaxReceiveSize>

If an alternate value is desired from the global value MaxReceiveSize, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41668r4_chk'
  tag severity: 'low'
  tag gid: 'V-33561'
  tag rid: 'SV-43981r3_rule'
  tag stig_id: 'Exch-2-705'
  tag gtitle: 'Exch-2-705'
  tag fix_id: 'F-37453r3_fix'
  tag 'documentable'
end
