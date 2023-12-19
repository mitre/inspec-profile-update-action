control 'SV-234773' do
  title 'Exchange Email Diagnostic log level must be set to lowest level.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Diagnostic logging, however, characteristically produces large volumes of data and requires care in managing the logs to prevent risk of disk capacity denial of service conditions. 

Exchange diagnostic logging is broken up into 29 main "services", each of which has anywhere from 2 to 26 "categories" of events to be monitored. Moreover, each category may be set to one of four levels of logging: Lowest, Low, Medium, and High, depending on how much detail one desires. The higher the level of detail, the more disk space required to store the audit material.

Diagnostic logging is intended to help administrators debug problems with their systems, not as a general purpose auditing tool. Because the diagnostic logs collect a great deal of information, the log files may grow large very quickly. Diagnostic log levels may be raised for limited periods of time when attempting to debug relevant pieces of Exchange functionality. Once debugging has finished, diagnostic log levels should be reduced again.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-EventLogLevel

If any Diagnostic EventLogLevel is not set to Lowest, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-EventLogLevel -Identity <'IdentityName\\EventlogName'> -Level Lowest

Note: The <IdentityName\\EventlogName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37959r617258_chk'
  tag severity: 'medium'
  tag gid: 'V-234773'
  tag rid: 'SV-234773r617260_rule'
  tag stig_id: 'EX13-CA-000045'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37922r617259_fix'
  tag 'documentable'
  tag legacy: ['SV-84353', 'V-69731']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
