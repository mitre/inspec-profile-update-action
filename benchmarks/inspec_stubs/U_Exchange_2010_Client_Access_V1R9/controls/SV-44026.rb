control 'SV-44026' do
  title 'Email Diagnostic log level must be set to low or lowest level.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Diagnostic logging, however, characteristically produces large volumes of data and requires care in managing the logs to prevent risk of disk capacity denial of service conditions. 
Exchange diagnostic logging is broken up into 29 main “services”, each of which has anywhere from 2 to 26 “categories” of events to be monitored. Moreover, each category may be set to one of four levels of logging: Lowest, Low, Medium, and High, depending on how much detail one desires. The higher the level of detail, the more disk space required to store the audit material.
Diagnostic logging is intended to help administrators debug problems with their systems, not as a general purpose auditing tool. Because the diagnostic logs collect a great deal of information, the log files may grow huge very quickly. Diagnostic log levels may be raised for limited periods of time when attempting to debug relevant pieces of Exchange functionality. Once debugging has finished, diagnostic log levels should be reduced again.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-EventLogLevel

If any Diagnostic “EventLevel” is not set to “Low” or “Lowest”, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-EventLogLevel -Identity <ServiceName\\Name> -Level Lowest 
  
or

Set-EventLogLevel -Identity <ServiceName\\Name> -Level Low'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41713r3_chk'
  tag severity: 'medium'
  tag gid: 'V-33606'
  tag rid: 'SV-44026r2_rule'
  tag stig_id: 'Exch-2-817'
  tag gtitle: 'Exch-2-817'
  tag fix_id: 'F-37498r3_fix'
  tag 'documentable'
end
