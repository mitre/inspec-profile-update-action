control 'SV-228360' do
  title 'Exchange Circular Logging must be disabled.'
  desc 'Logging provides a history of events performed and can also provide evidence of tampering or attack. Failure to create and preserve logs adds to the risk that suspicious events may go unnoticed and raises the potential that insufficient history will be available to investigate them. 

This setting controls how log files are written. If circular logging is enabled, one log file is stored with a default size of 1024 KB. Once the size limit has been reached, additional log entries overwrite the oldest log entries. If circular logging is disabled, once a log file reaches the size limit, a new log file is created. 

Mailbox should not use circular logging. Logs should be written to a partition separate from the operating system, with log protection and backups being incorporated into the overall System Security Plan.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, CircularLoggingEnabled

If the value of "CircularLoggingEnabled" is not set to "False", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'IdentityName'> -CircularLoggingEnabled $false

Note: The <IdentityName> value must be in single quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30593r496876_chk'
  tag severity: 'low'
  tag gid: 'V-228360'
  tag rid: 'SV-228360r879566_rule'
  tag stig_id: 'EX16-MB-000070'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-30578r496877_fix'
  tag 'documentable'
  tag legacy: ['SV-95345', 'V-80635']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
