control 'SV-228384' do
  title 'The Exchange Receive Connector Maximum Hop Count must be 60.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. This setting controls the maximum number of hops (email servers traversed) a message may take as it travels to its destination. Part of the original Internet protocol implementation, the hop count limit prevents a message being passed in a routing loop indefinitely. Messages exceeding the maximum hop count are discarded undelivered. 

Recent studies indicate that virtually all messages can be delivered in fewer than 60 hops. If the hop count is set too low, messages may expire before they reach their destinations. If the hop count is set too high, an undeliverable message may cycle between servers, raising the risk of network congestion.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine the Max Hop Count value for Receive connectors.

Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, MaxHopCount

For each Receive connector, if the value of "MaxHopCount" is not set to "60", this is a finding.

or

If the value of "MaxHopCount" is set to a value other than "60" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP to specify the "MaxHopCount" value or verify that this information is documented by the organization.

Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -MaxHopCount 60

or 

Enter the value as identified by the EDSP that has obtained a signoff with risk acceptance.

Repeat the procedure for each Receive connector.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30617r496948_chk'
  tag severity: 'low'
  tag gid: 'V-228384'
  tag rid: 'SV-228384r879651_rule'
  tag stig_id: 'EX16-MB-000380'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-30602r496949_fix'
  tag 'documentable'
  tag legacy: ['SV-95393', 'V-80683']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
