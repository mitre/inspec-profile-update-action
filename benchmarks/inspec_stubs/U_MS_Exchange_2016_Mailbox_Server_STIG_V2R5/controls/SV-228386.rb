control 'SV-228386' do
  title 'The Exchange Send connector connections count must be limited.'
  desc 'The Exchange Send connector setting controls the maximum number of simultaneous outbound connections allowed for a given SMTP connector and can be used to throttle the SMTP service if resource constraints warrant it. If the limit is too low, connections may be dropped. If the limit is too high, some domains may use a disproportionate resource share, denying access to other domains. Appropriate tuning reduces risk of data delay or loss.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the value for SMTP Server Maximum Outbound Connections.

Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MaxOutboundConnections

If the value of "MaxOutboundConnections" is not set to "1000", this is a finding.

or

If "MaxOutboundConnections" is set to a value other than "1000" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', %q(Update the EDSP to specify the "MaxOutboundConnections" value.

Open the Exchange Management Shell and enter the following command:

Set-TransportServer -Identity <'IdentityName'> -MaxOutboundConnections 1000

Note: The <IdentityName> value must be in single quotes.

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.)
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30619r496954_chk'
  tag severity: 'low'
  tag gid: 'V-228386'
  tag rid: 'SV-228386r879651_rule'
  tag stig_id: 'EX16-MB-000420'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30604r496955_fix'
  tag 'documentable'
  tag legacy: ['SV-95397', 'V-80687']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
