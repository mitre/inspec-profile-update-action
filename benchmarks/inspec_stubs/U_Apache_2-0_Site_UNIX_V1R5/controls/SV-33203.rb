control 'SV-33203' do
  title 'The sites error logs must log the correct format.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation. Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts. Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. The LogFormat directive defines the format and information to be included in the access log entries.'
  desc 'check', 'Enter the following command:

grep "LogFormat" /usr/local/apache2/conf/httpd.conf.

The command should return the following value: 

LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\" " combined.

If the above value is not returned, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and add LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\" " combined'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33744r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26280'
  tag rid: 'SV-33203r1_rule'
  tag stig_id: 'WA00612 A22'
  tag gtitle: 'WA00612'
  tag fix_id: 'F-29379r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2'
end
