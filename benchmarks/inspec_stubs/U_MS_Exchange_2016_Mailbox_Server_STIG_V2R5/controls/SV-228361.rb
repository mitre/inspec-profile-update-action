control 'SV-228361' do
  title 'Exchange Email Subject Line logging must be disabled.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. When "message tracking" is enabled, only the sender, recipients, time, and other delivery information is included by default. Information such as the subject and message body is not included.

However, the absence of the message subject line can make it difficult to locate a specific message in the log unless one knows roughly what time the message was sent. To simplify searches through these logs, Exchange offers the ability to include the message "subject line" in the log files and in the Message Tracking Center display. This can make it significantly easier to locate a specific message.

However, this feature creates larger log files and will contain information that may raise privacy and legal concerns. Enterprise policy should be consulted before this feature is enabled. Also, because the log files may contain sensitive information in the form of the subject line, the log files will need to be protected, commensurate with the sensitivity level, as the content may be of interest to an attacker.

For these reasons, it is recommended that subject logging not be enabled during regular production operations. Instead, treat this feature as a diagnostic that can be used if needed. The tradeoff is that finding the correct message in the message tracking logs will become more difficult because the administrator will need to search using only the time the message was sent and the message’s sender. This control will have no effect unless Message Tracking is enabled. However, the setting should be disabled in case message tracking is enabled in the future.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, MessageTrackingLogSubjectLoggingEnabled

If the value of “MessageTrackingLogSubjectLoggingEnabled” is not set to “False”, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-Transportservice -MessageTrackingLogSubjectLoggingEnabled $False'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30594r496879_chk'
  tag severity: 'medium'
  tag gid: 'V-228361'
  tag rid: 'SV-228361r879566_rule'
  tag stig_id: 'EX16-MB-000080'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-30579r496880_fix'
  tag 'documentable'
  tag legacy: ['SV-95347', 'V-80637']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
