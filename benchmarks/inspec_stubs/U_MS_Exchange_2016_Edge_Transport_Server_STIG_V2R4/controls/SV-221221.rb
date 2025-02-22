control 'SV-221221' do
  title 'Exchange Outbound Connection Limit per Domain Count must be controlled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This configuration controls the maximum number of simultaneous outbound connections from a domain and works in conjunction with the Maximum Outbound Connections Count setting as a delivery tuning mechanism. If the limit is too low, connections may be dropped. If the limit is too high, some domains may use a disproportionate resource share, denying access to other domains. Appropriate tuning reduces the risk of data delay or loss. 

By default, a limit of 20 simultaneous outbound connections from a domain should be sufficient. The value may be adjusted if justified by local site conditions.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the value for Maximum Domain Connections.

Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MaxPerDomainOutboundConnections

If the value of "MaxPerDomainOutboundConnections" is not set to "20", this is a finding.

or

If the value of "MaxPerDomainOutboundConnections" is set to a value other than "20" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP to reflect the value for Maximum Domain Connections.

Open the Exchange Management Shell and enter the following command:

Set-TransportService -Identity <'IdentityName'> -MaxPerDomainOutboundConnections 20

Note: The <IdentityName> value must be in single quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22936r411789_chk'
  tag severity: 'medium'
  tag gid: 'V-221221'
  tag rid: 'SV-221221r612603_rule'
  tag stig_id: 'EX16-ED-000200'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22925r411790_fix'
  tag 'documentable'
  tag legacy: ['SV-95233', 'V-80523']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
