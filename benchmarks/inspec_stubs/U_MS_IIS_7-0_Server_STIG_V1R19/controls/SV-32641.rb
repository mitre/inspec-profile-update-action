control 'SV-32641' do
  title 'Monitoring software must include CGI type files or equivalent programs.'
  desc 'By their very nature, CGI type files permit the anonymous web user to interact with data and perhaps store data on the web server. In many cases, CGI scripts exercise system-level control over the server’s resources. These files make appealing targets for the malicious user. If these files can be modified or exploited, the web server can be compromised. CGI or equivalent files must be monitored by a security tool alerting the web administrator of any unauthorized changes.'
  desc 'check', 'Request to see the template file or configuration file of the software being used to accomplish this security task. The monitoring program should provide constant monitoring for these files, and instantly alert the web administrator of any unauthorized changes. Example CGI file extensions include, but are not limited to, .cgi, .class, .vb, .php, .pl, and .c.

If the monitoring product configuration does not monitor changes to CGI program files, this is a finding.'
  desc 'fix', 'Configure the monitoring tool to include CGI type files or equivalent programs directory.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32951r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2271'
  tag rid: 'SV-32641r3_rule'
  tag stig_id: 'WG440 IIS7'
  tag gtitle: 'WG440'
  tag fix_id: 'F-26839r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
