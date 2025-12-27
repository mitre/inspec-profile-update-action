control 'SV-43984' do
  title 'Receive Connector timeout must be limited.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning.   This configuration controls the number of idle minutes before the connection is dropped.   It works in conjunction with the Maximum Inbound Connections Count setting.  

Connections, once established, may incur delays in message transfer.   If the timeout period is too long, there is risk that idle connections may be maintained for unnecessarily long time periods, preventing new connections from being established.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the 'Connection Timeout' value.  

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, ConnectionTimeout

If the value of 'ConnectionTimeout' is set to 00:10:00, this is not a finding.

If 'ConnectionTimeout' is set to other than 00:10:00, and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -ConnectionTimeout 00:10:00 or other value as identified by the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41670r1_chk'
  tag severity: 'low'
  tag gid: 'V-33564'
  tag rid: 'SV-43984r1_rule'
  tag stig_id: 'Exch-2-710'
  tag gtitle: 'Exch-2-710'
  tag fix_id: 'F-37456r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
