control 'SV-228390' do
  title 'The Exchange Outbound Connection Timeout must be 10 minutes or less.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This configuration controls the number of idle minutes before the connection is dropped. It works in conjunction with the Maximum Outbound Connections Count setting.

Connections, once established, may incur delays in message transfer. The default of 10 minutes is a reasonable window in which to resume activities without maintaining idle connections for excessive intervals. If the timeout period is too long, idle connections may be maintained for unnecessarily long time periods, preventing new connections from being established. Sluggish connectivity increases the risk of lost data. A value of "10" or less is optimal.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information.

Determine the Connection Timeout value.

Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, ConnectionInactivityTimeOut 

For each Send connector, if the value of "ConnectionInactivityTimeOut" is not set to "00:10:00", this is a finding.

or

If "ConnectionInactivityTimeOut" is set to a value other than "00:10:00" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', %q(Update the EDSP to specify the "ConnectionInactivityTimeOut" value.

Open the Exchange Management Shell and enter the following command:

Set-SendConnector -Identity <'IdentityName'> -ConnectionInactivityTimeOut  00:10:00

Note: The <IdentityName> value must be in single quotes.

or

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.)
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30623r496966_chk'
  tag severity: 'low'
  tag gid: 'V-228390'
  tag rid: 'SV-228390r612748_rule'
  tag stig_id: 'EX16-MB-000460'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30608r496967_fix'
  tag 'documentable'
  tag legacy: ['V-80695', 'SV-95405']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
