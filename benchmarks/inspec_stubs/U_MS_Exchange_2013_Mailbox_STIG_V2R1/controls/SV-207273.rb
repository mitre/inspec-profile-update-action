control 'SV-207273' do
  title 'Exchange Circular Logging must be disabled.'
  desc 'Logging provides a history of events performed and can also provide evidence of tampering or attack. Failure to create and preserve logs adds to the risk that suspicious events may go unnoticed and raises the potential that insufficient history will be available to investigate them. 

This setting controls how log files are written. If circular logging is enabled, there is one log file stored with a default size of 1024 KB. Once the size limit has been reached, additional log entries overwrite the oldest log entries. If circular logging is disabled, once a log file reaches the size limit, a new log file is created. 

Mailbox should not use circular logging. Logs should be written to a partition separate from the operating system, with log protection and backups being incorporated into the overall System Security plan.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, CircularLoggingEnabled

If the value of CircularLoggingEnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'IdentityName'> -CircularLoggingEnabled $false

Note: The <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7531r393332_chk'
  tag severity: 'low'
  tag gid: 'V-207273'
  tag rid: 'SV-207273r615936_rule'
  tag stig_id: 'EX13-MB-000035'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-7531r393333_fix'
  tag 'documentable'
  tag legacy: ['SV-84575', 'V-69953']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
