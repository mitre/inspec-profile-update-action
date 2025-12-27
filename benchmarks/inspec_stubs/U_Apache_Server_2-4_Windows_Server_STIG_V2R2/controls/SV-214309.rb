control 'SV-214309' do
  title 'System logging must be enabled.'
  desc 'The server error logs are invaluable because they can also be used to identify potential problems and enable proactive remediation. Log data can reveal anomalous behavior such as “not found” or “unauthorized” errors that may be an evidence of attack attempts. Failure to enable error logging can significantly reduce the ability of Web Administrators to detect or remediate problems. The CustomLog directive specifies the log file, syslog facility, or piped logging utility.'
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". 
Edit the "httpd.conf" file and Search for the directive "CustomLog".

If the "CustomLog" directive is missing or does not look like the following, this is a finding:

CustomLog "Logs/access_log" common)
  desc 'fix', 'Edit the httpd.conf file and enter the name, path and level for the CustomLog.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15521r277430_chk'
  tag severity: 'medium'
  tag gid: 'V-214309'
  tag rid: 'SV-214309r505936_rule'
  tag stig_id: 'AS24-W1-000065'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15519r277431_fix'
  tag 'documentable'
  tag legacy: ['SV-102425', 'V-92337']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
