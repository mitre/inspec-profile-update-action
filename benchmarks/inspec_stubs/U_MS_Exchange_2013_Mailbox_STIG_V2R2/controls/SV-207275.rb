control 'SV-207275' do
  title 'Exchange Message Tracking Logging must be enabled.'
  desc 'A message tracking log provides a detailed log of all message activity as messages are transferred to and from a computer running Exchange.

If events are not recorded, it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MessageTrackingLogEnabled

If the value of MessageTrackingLogEnabled is not set to “True”, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-TransportService -Identity <'IdentityName'> - MessageTrackingLogEnabled $True

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7533r393338_chk'
  tag severity: 'medium'
  tag gid: 'V-207275'
  tag rid: 'SV-207275r615936_rule'
  tag stig_id: 'EX13-MB-000045'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-7533r393339_fix'
  tag 'documentable'
  tag legacy: ['SV-84579', 'V-69957']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
