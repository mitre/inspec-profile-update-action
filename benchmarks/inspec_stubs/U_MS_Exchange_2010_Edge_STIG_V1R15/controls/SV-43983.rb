control 'SV-43983' do
  title 'Internet Receive Connector connections count must be set to default.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. This configuration controls the maximum number of simultaneous inbound connections allowed to the SMTP server. 

By default, the number of simultaneous inbound connections is 5000. If a limit is set too low, the connections pool may get filled. If attackers perceive the limit is too low, they could deny service to the Simple Mail Transfer Protocol (SMTP) server by using a connection count that exceeds the limit set. By setting the default configuration to 5000, attackers would need many more connections to cause denial of service.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the 'Maximum Inbound connections' value. 

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxInboundConnection

Identify Internet-facing connectors on the Edge Transport server. 

If 'MaxInboundConnection' is set to a different numeric value or unlimited, and has signoff and risk acceptance in the EDSP, this is not a finding.

If the value of 'MaxInboundConnection' is not set to 5000, this is a finding."
  desc 'fix', "Noting the Internet-facing receive connector name,  open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -MaxInboundConnection unlimited 

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41669r2_chk'
  tag severity: 'low'
  tag gid: 'V-33563'
  tag rid: 'SV-43983r2_rule'
  tag stig_id: 'Exch-2-708'
  tag gtitle: 'Exch-2-708'
  tag fix_id: 'F-37455r1_fix'
  tag 'documentable'
end
