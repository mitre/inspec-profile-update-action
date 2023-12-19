control 'SV-33192' do
  title 'Error logging must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation.  . Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts.   Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems.'
  desc 'check', 'Enter the following command:

grep "ErrorLog" /usr/local/apache2/conf/httpd.conf

This directive lists the name and location of the error log. 
 
If the command result lists no data, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and enter the name and path to the ErrorLog.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26279'
  tag rid: 'SV-33192r1_rule'
  tag stig_id: 'WA00605 A22'
  tag gtitle: 'WA00605'
  tag fix_id: 'F-29376r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
