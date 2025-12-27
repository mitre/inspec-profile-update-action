control 'SV-228399' do
  title 'The Exchange Receive connector timeout must be limited.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning. This configuration controls the number of idle minutes before the connection is dropped. It works in conjunction with the Maximum Inbound Connections Count setting. 

Connections, once established, may incur delays in message transfer. If the timeout period is too long, there is risk that idle connections may be maintained for unnecessarily long time periods, preventing new connections from being established.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the Connection Timeout value. 

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, ConnectionTimeout

For each Receive connector, if the value of "ConnectionTimeout" is not set to "00:10:00", this is a finding.

or

If "ConnectionTimeout" is set to other than "00:10:00" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP to specify the Connection Timeout value.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -ConnectionTimeout 00:10:00

Note: The <IdentityName> value must be in single quotes.

or 

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30632r496993_chk'
  tag severity: 'low'
  tag gid: 'V-228399'
  tag rid: 'SV-228399r612748_rule'
  tag stig_id: 'EX16-MB-000550'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-30617r496994_fix'
  tag 'documentable'
  tag legacy: ['SV-95423', 'V-80713']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
