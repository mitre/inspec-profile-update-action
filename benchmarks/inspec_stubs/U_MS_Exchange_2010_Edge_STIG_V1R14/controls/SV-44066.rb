control 'SV-44066' do
  title 'Outbound Connection Timeout must be 10 or less.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. This configuration controls the number of idle minutes before the connection is dropped. It works in conjunction with the Maximum Outbound Connections Count setting.

Connections, once established, may incur delays in message transfer. The default of 10 minutes is a reasonable window in which to resume activities without maintaining idle connections for excessive intervals. If the timeout period is too long, idle connections may be maintained for unnecessarily long time periods, preventing new connections from being established. Sluggish connectivity increases the risk of lost data. A value of 10 or less is optimal.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the 'Connection Timeout' value.  

Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, ConnectionInactivityTimeOut 

If the value of 'ConnectionInactivityTimeOut' is set to 00:10:00, this is not a finding.

If 'ConnectionInactivityTimeOut' is set to other than 00:10:00, and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -ConnectionInactivityTimeOut 
 00:10:00 or other value as identified by the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41756r1_chk'
  tag severity: 'low'
  tag gid: 'V-33646'
  tag rid: 'SV-44066r1_rule'
  tag stig_id: 'Exch-2-769'
  tag gtitle: 'Exch-2-769'
  tag fix_id: 'F-37539r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
