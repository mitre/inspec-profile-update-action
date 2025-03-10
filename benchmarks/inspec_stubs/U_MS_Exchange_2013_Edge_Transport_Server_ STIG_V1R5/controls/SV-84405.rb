control 'SV-84405' do
  title 'Exchange must limit the Receive connector timeout.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning. This configuration controls the number of idle minutes before the connection is dropped. It works in conjunction with the Maximum Inbound Connections Count setting.  

Connections, once established, may incur delays in message transfer. If the timeout period is too long, there is risk that connections may be maintained for unnecessarily long time periods, preventing new connections from being established.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the connection Timeout value.  

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, ConnectionTimeout

For each Receive connector, if the value of ConnectionTimeout is not set to 00:05:00, this is a finding.

or

If ConnectionTimeout is set to another value other than 00:05:00 and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -ConnectionTimeout 00:05:00 

Note: The <IdentityName> value must be in single quotes.

or 

The value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69783'
  tag rid: 'SV-84405r1_rule'
  tag stig_id: 'EX13-EG-000005'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-75995r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
