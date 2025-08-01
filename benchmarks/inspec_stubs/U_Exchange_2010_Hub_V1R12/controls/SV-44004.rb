control 'SV-44004' do
  title 'Send Connectors must be clearly named.'
  desc 'For send connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively,  connectors should account for all connections required for the overall email topology design.  Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity

Review the naming for connectors. If the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Name <'NewName'> -Identity <'SendConnector'>"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41689r1_chk'
  tag severity: 'low'
  tag gid: 'V-33583'
  tag rid: 'SV-44004r1_rule'
  tag stig_id: 'Exch-2-751'
  tag gtitle: 'Exch-2-751'
  tag fix_id: 'F-37474r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
