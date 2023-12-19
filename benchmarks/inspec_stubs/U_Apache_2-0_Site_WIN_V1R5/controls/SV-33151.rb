control 'SV-33151' do
  title 'System logging must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation. Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts.   Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. The CustomLog directive specifies the log file, syslog facility, or piped logging utility.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives: CustomLog

If any enabled CustomLog are not set to logs/access_log combined, this is a finding.

Note: This check is applicable to every host and virtual host the web server is supporting.'
  desc 'fix', 'Edit the httpd.conf file and enter the name, path and level for the CustomLog.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26281'
  tag rid: 'SV-33151r1_rule'
  tag stig_id: 'WA00615 W22'
  tag gtitle: 'WA00615'
  tag fix_id: 'F-29381r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAR-1'
end
