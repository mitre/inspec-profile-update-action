control 'SV-33206' do
  title 'System logging must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation. Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts.   Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. The CustomLog directive specifies the log file, syslog facility, or piped logging utility.'
  desc 'check', 'Enter the following command:

grep "CustomLog" /usr/local/apache2/conf/httpd.conf

The command should return the following value:.

CustomLog "Logs/access_log" common

If the above value is not returned, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and configure to load the log_config_module. Configure with ErrorLog and CustomLog directives to ensure comprehensive system and access logging.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33746r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26281'
  tag rid: 'SV-33206r1_rule'
  tag stig_id: 'WA00615 A22'
  tag gtitle: 'WA00615'
  tag fix_id: 'F-29381r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
