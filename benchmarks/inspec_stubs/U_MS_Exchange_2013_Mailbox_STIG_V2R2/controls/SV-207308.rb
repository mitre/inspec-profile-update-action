control 'SV-207308' do
  title 'The Exchange Send connector connections count must be limited.'
  desc 'The Exchange Send connector setting controls the maximum number of simultaneous outbound connections allowed for a given SMTP connector and can be used to throttle the SMTP service if resource constraints warrant it. If the limit is too low, connections may be dropped. If too high, some domains may use a disproportionate resource share, denying access to other domains. Appropriate tuning reduces risk of data delay or loss.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the value for SMTP Server Maximum Outbound Connections.

Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MaxOutboundConnections

If the value of MaxOutboundConnections is not set to 1000, this is a finding.

or

If the value of MaxOutboundConnections is set to a value other than 1000 and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-TransportServer -Identity <'IdentityName'> -MaxOutboundConnections 1000

Note: The <IdentityName> value must be in quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7566r393437_chk'
  tag severity: 'low'
  tag gid: 'V-207308'
  tag rid: 'SV-207308r615936_rule'
  tag stig_id: 'EX13-MB-000210'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7566r393438_fix'
  tag 'documentable'
  tag legacy: ['SV-84645', 'V-70023']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
