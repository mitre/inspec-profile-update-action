control 'SV-33149' do
  title 'The sites error logs must log the correct format.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation.  Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts.   Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive:  LogFormat

The minimum items to be logged are as shown in the sample below:

LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\"" combined

Verify the information following the LogFormat directive meets or exceeds the minimum requirement above. If any LogFormat directive does not meet this requirement, this is a finding.'
  desc 'fix', 'Edit the configuration file/s and add LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\"" combined'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33800r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26280'
  tag rid: 'SV-33149r1_rule'
  tag stig_id: 'WA00612 W22'
  tag gtitle: 'WA00612'
  tag fix_id: 'F-29443r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2'
end
