control 'SV-221227' do
  title 'Exchange Receive connectors must be clearly named.'
  desc 'For receive connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively, connectors should account for all connections required for the overall email topology design. Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity

For each Receive connector, review the naming for connectors.

If the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Name <'NewName'> -Identity <'IdentityName'>

Note: Both the <NewName> and <IdentityName> value must be in single quotes.

Repeat the procedure for each receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22942r495389_chk'
  tag severity: 'low'
  tag gid: 'V-221227'
  tag rid: 'SV-221227r612603_rule'
  tag stig_id: 'EX16-ED-000280'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22931r411808_fix'
  tag 'documentable'
  tag legacy: ['SV-95245', 'V-80535']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
