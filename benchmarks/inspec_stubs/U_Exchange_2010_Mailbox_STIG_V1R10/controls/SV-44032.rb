control 'SV-44032' do
  title 'Circular Logging must be disabled.'
  desc 'Logging provides a history of events performed, and can also provide evidence of tampering or attack. Failure to create and preserve logs adds to the risk that suspicious events may go unnoticed, or the raise the potential that insufficient history will be available to investigate them. 

This setting controls how log files are written. If circular logging is enabled, there is one log file stored with a default size of 1024 KB. Once the size limit has been reached, additional log entries overwrite the oldest log entries. If circular logging is disabled, once a log file reaches the size limit, a new log file is created. 

Mailbox should not use circular logging. Logs should be written to a partition separate from the operating system, with log protection and backups being incorporated into the overall System Security plan.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase -Server <'ServerUnderReview'>| Select Name, Identity, CircularLoggingEnabled

If the value of 'CircularLoggingEnabled' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'MailboxDatabase'> -CircularLoggingEnabled $false"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41719r1_chk'
  tag severity: 'low'
  tag gid: 'V-33612'
  tag rid: 'SV-44032r2_rule'
  tag stig_id: 'Exch-1-802'
  tag gtitle: 'Exch-1-802'
  tag fix_id: 'F-37504r1_fix'
  tag 'documentable'
end
