control 'SV-33153' do
  title 'The LogLevel directive must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation.  Log data can reveal anomalous behavior such as  “not found” or “unauthorized” errors that may be an evidence of attack attempts.   Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. While the ErrorLog directive configures the error log file name, the LogLevel directive is used to configure the severity level for the error logs. The log level values are the standard syslog levels: emerg, alert, crit, error, warn, notice, info and debug.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: LogLevel

All enabled LogLevel directives should be set to a minimum of “warn”, if not, this is a finding.

Note:  If LogLevel is set to error, crit, alert, or emerg which are higher thresholds this is not a finding.'
  desc 'fix', 'Edit the httpd.conf file and add the value LogLevel warn.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33802r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26282'
  tag rid: 'SV-33153r1_rule'
  tag stig_id: 'WA00620 W22'
  tag gtitle: 'WA00620'
  tag fix_id: 'F-29446r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
