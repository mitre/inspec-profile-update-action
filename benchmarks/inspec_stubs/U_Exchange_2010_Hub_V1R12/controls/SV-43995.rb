control 'SV-43995' do
  title 'Receive Connectors must be clearly named.'
  desc 'For receive connectors, unclear naming as to direction and purpose increases risk that messages may not flow as intended, troubleshooting efforts may be impaired, or incorrect assumptions may be made about the completeness of the configuration.  

Collectively,  connectors should account for all connections required for the overall email topology design.  Simple Mail Transfer Protocol (SMTP) connectors, when listed, must name purpose and direction clearly, and their counterparts on servers to which they connect should be recognizable as their partners.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity

Review the naming for connectors. If the connectors are not clearly named for purpose and direction, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Name <'NewName'> -Identity <'ReceiveConnector'>"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41681r1_chk'
  tag severity: 'low'
  tag gid: 'V-33575'
  tag rid: 'SV-43995r1_rule'
  tag stig_id: 'Exch-2-733'
  tag gtitle: 'Exch-2-733'
  tag fix_id: 'F-37466r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
