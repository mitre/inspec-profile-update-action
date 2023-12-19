control 'SV-207305' do
  title 'Exchange Send connectors must be clearly named.'
  desc 'For Send connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively, connectors should account for all connections required for the overall email topology design. Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity

Determine the naming for the Send connectors. 

For each Send connector, if the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Name <'NewSendConnectorName'> -Identity <'IdentityName'>

Note: Both the <NewSendConnectorName> and <IdentityName> value must be in quotes.

Repeat the procedure for each Send connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7563r393428_chk'
  tag severity: 'low'
  tag gid: 'V-207305'
  tag rid: 'SV-207305r615936_rule'
  tag stig_id: 'EX13-MB-000195'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7563r393429_fix'
  tag 'documentable'
  tag legacy: ['SV-84639', 'V-70017']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
