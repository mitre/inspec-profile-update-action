control 'SV-44034' do
  title 'Email Subject Line logging must be disabled.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability.  When “message tracking” is enabled, only the sender, recipients, time, and other delivery information are included by default.   Information such as the subject and message body is not included.  

However, the absence of the message subject line can make it difficult to locate a specific message in the log unless one knows roughly what time the message was sent.  To simplify searches through these logs, Exchange offers the ability to include the message “subject line” in the log files and in the Message Tracking Center display.  This can make it significantly easier to locate a specific message.  

This feature creates larger log files and will contain information that may raise privacy and legal concerns - enterprise policy should be consulted before this feature is enabled. Also, since the log files may contain sensitive information in the form of the subject line, the log files will need to be protected, commensurate with the sensitivity level, as the content may be of interest to an attacker.  

For these reasons, it is recommended that subject logging not be enabled during regular production operations, but instead treat this feature as a diagnostic that can be used if needed. The tradeoff of this is that finding the correct message in the message tracking logs will become more difficult since the administrator will need to search using only the time the message was sent and the message’s sender.  This control will have no effect unless Message Tracking is enabled. That said, the setting should be disabled in case message tracking is perchance enabled at a future time.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-MailboxServer | Select Name, Identity, MessageTrackingLogSubjectLoggingEnabled

If the value of 'MessageTrackingLogSubjectLoggingEnabled' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxServer -Identity <'ServerName'> -MessageTrackingLogSubjectLoggingEnabled $false"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33614'
  tag rid: 'SV-44034r1_rule'
  tag stig_id: 'Exch-1-805'
  tag gtitle: 'Exch-1-805'
  tag fix_id: 'F-37506r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
