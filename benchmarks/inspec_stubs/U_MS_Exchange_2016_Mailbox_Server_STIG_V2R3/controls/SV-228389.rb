control 'SV-228389' do
  title 'The Exchange Outbound Connection Limit per Domain Count must be controlled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This configuration controls the maximum number of simultaneous outbound connections from a domain as a delivery tuning mechanism. If the limit is too low, connections may be dropped. If the limit is too high, some domains may use a disproportionate resource share, denying access to other domains. Appropriate tuning reduces risk of data delay or loss. 

By default, a limit of 20 simultaneous outbound connections from a domain should be sufficient. The value may be adjusted if justified by local site conditions.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information.

Determine the value for Maximum Outbound Domain Connections.

Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MaxPerDomainOutboundConnections

If the value of "MaxPerDomainOutboundConnections" is not set to "20", this is a finding.

or

If "MaxPerDomainOutboundConnections" is set to a value other than "20" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', %q(Update the EDSP to specify the "MaxPerDomainOutboundConnection" value or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-TransportService -Identity <'IdentityName'> -MaxPerDomainOutboundConnections 20

Note: The <IdentityName> value must be in single quotes.

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.)
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30622r496963_chk'
  tag severity: 'low'
  tag gid: 'V-228389'
  tag rid: 'SV-228389r612748_rule'
  tag stig_id: 'EX16-MB-000450'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30607r496964_fix'
  tag 'documentable'
  tag legacy: ['SV-95403', 'V-80693']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
