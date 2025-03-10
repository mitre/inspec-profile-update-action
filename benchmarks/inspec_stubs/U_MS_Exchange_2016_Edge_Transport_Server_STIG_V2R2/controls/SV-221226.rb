control 'SV-221226' do
  title 'Exchange Receive connector Maximum Hop Count must be 60.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This setting controls the maximum number of hops (email servers traversed) a message may take as it travels to its destination. Part of the original Internet protocol implementation, the hop count limit prevents a message from being passed in a routing loop indefinitely. Messages exceeding the maximum hop count are discarded undelivered. 

Recent studies indicate that virtually all messages can be delivered in fewer than 60 hops. If the hop count is set too low, messages may expire before they reach their destinations. If set too high, an undeliverable message may cycle between servers, raising the risk of network congestion.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the value for Receive connectors.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, MaxHopCount

For each receive connector, if the value of "MaxHopCount" is not set to "60", this is a finding.  

or 

If the value of "MaxHopCount" is set to a value other than "60" and has signoff and risk acceptance, this is not a finding.'
  desc 'fix', "Update the EDSP to reflect the value for Receive connectors.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -MaxHopCount 60

Note: The <IdentityName> value must be in single quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22941r411804_chk'
  tag severity: 'medium'
  tag gid: 'V-221226'
  tag rid: 'SV-221226r612603_rule'
  tag stig_id: 'EX16-ED-000270'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-22930r411805_fix'
  tag 'documentable'
  tag legacy: ['SV-95243', 'V-80533']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
