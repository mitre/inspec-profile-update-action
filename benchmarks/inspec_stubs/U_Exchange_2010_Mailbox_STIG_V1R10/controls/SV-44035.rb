control 'SV-44035' do
  title 'Message Tracking Logging must be enabled.'
  desc 'A message tracking log provides a detailed log of all message activity as messages are transferred to and from a computer running Exchange.

If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-MailboxServer | Select Name, Identity, MessageTrackingLogEnabled

If the value of 'MessageTrackingLogEnabled' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxServer -Identity <'ServerName'> -MessageTrackingLogEnable $True"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41722r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33615'
  tag rid: 'SV-44035r1_rule'
  tag stig_id: 'Exch-1-808'
  tag gtitle: 'Exch-1-808'
  tag fix_id: 'F-37507r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
