control 'SV-84459' do
  title 'Exchange Receive connectors must be clearly named.'
  desc 'For receive connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively, connectors should account for all connections required for the overall email topology design. Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity

For each Receive connector, review the naming for connectors.

If the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Name <'NewName'> -Identity <'IdentityName'>

Note: Both the <NewName> and <IdentityName> value must be in quotes.

Repeat the procedure for each Receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70307r1_chk'
  tag severity: 'low'
  tag gid: 'V-69837'
  tag rid: 'SV-84459r1_rule'
  tag stig_id: 'EX13-EG-000140'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-76067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
