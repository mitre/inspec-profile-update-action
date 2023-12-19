control 'SV-43999' do
  title 'Receive Connector Maximum Hop Count must be 60.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. This setting controls the maximum number of hops (email servers traversed) a message may take as it travels to its destination. Part of the original Internet protocol implementation, the hop count limit prevents a message being passed in a routing loop indefinitely. Messages exceeding the maximum hop count are discarded undelivered. 

Recent studies indicate that virtually all messages can be delivered in fewer than 60 hops. If the hop count is set too low, messages may expire before they reach their destinations. If set too high, an undeliverable message may cycle between servers, raising the risk of network congestion.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the value for 'Receive Connectors”.
Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select name, MaxHopCount

If the value of 'MaxHopCount' is set to 60 this is not a finding.

If the value of 'MaxHopCount' is set to a value other than 60 and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -MaxHopCount 60

If an alternate value is desired, obtain signoff with risk acceptance and document in the EDSP.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41685r3_chk'
  tag severity: 'low'
  tag gid: 'V-33579'
  tag rid: 'SV-43999r2_rule'
  tag stig_id: 'Exch-2-741'
  tag gtitle: 'Exch-2-741'
  tag fix_id: 'F-37470r1_fix'
  tag 'documentable'
end
