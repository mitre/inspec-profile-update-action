control 'SV-221228' do
  title 'Exchange Receive connectors must control the number of recipients chunked on a single message.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. For message size restrictions, multiple places exist to set or override inbound or outbound message size. Failure to control the configuration strategy can result in loss of data or system availability.
 
This setting enables the administrator to enable "chunking" on received messages as they arrive at the domain. This is done so large message bodies can be relayed by the remote sender to the Receive connector in multiple, smaller chunks.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, ChunkingEnabled

For each receive connector, if the value of "ChunkingEnabled" is not set to "True", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -ChunkingEnabled $true

Note: The <IdentityName> value must be in single quotes.

Repeat the procedure for each receive connector."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22943r411810_chk'
  tag severity: 'low'
  tag gid: 'V-221228'
  tag rid: 'SV-221228r612603_rule'
  tag stig_id: 'EX16-ED-000290'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22932r411811_fix'
  tag 'documentable'
  tag legacy: ['SV-95247', 'V-80537']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
