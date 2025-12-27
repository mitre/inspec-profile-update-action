control 'SV-33151' do
  title 'System logging must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation. Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts. Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. 
The mod_log_config module provides for flexible logging of client requests. Logs are written in a customizable format, and may be written directly to a file, or to an external program. Conditional logging is provided so that individual requests may be included or excluded from the logs based on characteristics of the request.
Three directives are provided by this module: TransferLog to create a log file, LogFormat to set a custom format, and CustomLog to define a log file and format in one step. The TransferLog and CustomLogdirectives can be used multiple times in each server to cause each request to be logged to multiple files.
The server error log, whose name and location is set by the ErrorLog directive, is the most important log file. This is the place where Apache httpd will send diagnostic information and record any errors that it encounters in processing requests. It is the first place to look when a problem occurs with starting the server or with the operation of the server, since it will often contain details of what went wrong and how to fix it.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.
Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives: 
LoadModule log_config_module modules/mod_log_config.so
If the LoadModule log_config_module directive is commented out or does not exist, this is a finding.

Search for both of the following uncommented directives: ErrorLog and CustomLog.  
If no uncommented directives for both ErrorLog and CustomLog are found, this is a finding.
Note: This check is applicable to every host and virtual host the web server is supporting.'
  desc 'fix', 'Edit the httpd.conf file and configure to load the log_config_module. Configure with ErrorLog and CustomLog directives to ensure comprehensive system and access logging.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33801r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26281'
  tag rid: 'SV-33151r2_rule'
  tag stig_id: 'WA00615 W22'
  tag gtitle: 'WA00615'
  tag fix_id: 'F-29381r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
