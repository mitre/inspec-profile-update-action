control 'SV-43994' do
  title 'Receive Connectors must control the number of recipients chunked on a single message.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability.
 
This setting enables the administrator to enable ‘chunking’ on received messages as they arrive at the domain.  This is done so that large message bodies can be relayed by the remote sender to the receive connector in multiple, smaller chunks.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, ChunkingEnabled

If the value of 'ChunkingEnabled' is set to 'True', this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'>  -ChunkingEnabled $true"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41680r1_chk'
  tag severity: 'low'
  tag gid: 'V-33574'
  tag rid: 'SV-43994r1_rule'
  tag stig_id: 'Exch-2-730'
  tag gtitle: 'Exch-2-730'
  tag fix_id: 'F-37465r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
