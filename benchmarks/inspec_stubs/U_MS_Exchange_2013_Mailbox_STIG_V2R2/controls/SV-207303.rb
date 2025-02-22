control 'SV-207303' do
  title 'Exchange Receive connectors must be clearly named.'
  desc 'For Receive connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively, connectors should account for all connections required for the overall email topology design. Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity

Review the naming for connectors.

If the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Name <'NewReceiveConnectorName'> -Identity <'IdentityName'>

Note: Both the <NewSendReceiveName> and <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7561r393422_chk'
  tag severity: 'low'
  tag gid: 'V-207303'
  tag rid: 'SV-207303r615936_rule'
  tag stig_id: 'EX13-MB-000185'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7561r393423_fix'
  tag 'documentable'
  tag legacy: ['SV-84635', 'V-70013']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
