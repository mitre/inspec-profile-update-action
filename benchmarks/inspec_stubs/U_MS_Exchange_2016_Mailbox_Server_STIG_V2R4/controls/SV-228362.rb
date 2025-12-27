control 'SV-228362' do
  title 'Exchange Message Tracking Logging must be enabled.'
  desc 'A message tracking log provides a detailed log of all message activity as messages are transferred to and from a computer running Exchange.

If events are not recorded, it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-Transportservice  | Select Name, MessageTrackingLogEnabled

If the value of MessageTrackingLogEnabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-Transportservice <IdentityName> -MessageTrackingLogEnabled $true

Note: The <IdentityName> value must be in quotes.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30595r496882_chk'
  tag severity: 'medium'
  tag gid: 'V-228362'
  tag rid: 'SV-228362r612748_rule'
  tag stig_id: 'EX16-MB-000090'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-30580r496883_fix'
  tag 'documentable'
  tag legacy: ['SV-95349', 'V-80639']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
