control 'SV-84479' do
  title 'The Exchange Internet Receive connector connections count must be set to default.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This configuration controls the maximum number of simultaneous inbound connections allowed to the SMTP server. 

By default, the number of simultaneous inbound connections is 5000. If a limit is set too low, the connections pool may be filled. If attackers perceive the limit is too low, they could deny service to the Simple Mail Transfer Protocol (SMTP) server by using a connection count that exceeds the limit set. By setting the default configuration to 5000, attackers would need many more connections to cause denial of service.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the Maximum Inbound connections value. 

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxInboundConnection

Identify Internet-facing connectors.

For each Receive connector, if the value of MaxInboundConnection is not set to 5000, this is a finding.

or

If MaxInboundConnection is set to a value other than 5000 or is set to unlimited and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxInboundConnection 5000

Note: The <IdentityName> value must be in quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each Receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70557r1_chk'
  tag severity: 'low'
  tag gid: 'V-69857'
  tag rid: 'SV-84479r1_rule'
  tag stig_id: 'EX13-EG-000155'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-76087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
