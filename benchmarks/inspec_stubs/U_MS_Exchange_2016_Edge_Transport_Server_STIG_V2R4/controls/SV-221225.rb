control 'SV-221225' do
  title 'Exchange Send connectors must be clearly named.'
  desc 'For Send connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively, connectors should account for all connections required for the overall email topology design. Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity

Review the naming for connectors. 

For each send connector, if the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Name <'NewName'> -Identity <'IdentityName'>

Note: Both the <NewName> and <IdentityName> values must be in single quotes.

Repeat the procedure for each send connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22940r411801_chk'
  tag severity: 'low'
  tag gid: 'V-221225'
  tag rid: 'SV-221225r612603_rule'
  tag stig_id: 'EX16-ED-000260'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22929r411802_fix'
  tag 'documentable'
  tag legacy: ['SV-95241', 'V-80531']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
