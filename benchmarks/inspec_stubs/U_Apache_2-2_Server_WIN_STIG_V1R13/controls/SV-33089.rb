control 'SV-33089' do
  title 'Monitoring software must include CGI or equivalent programs in its scope.'
  desc 'By their very nature, CGI type files permit the anonymous web user to interact with data and perhaps store data on the web server. In many cases, CGI scripts exercise system-level control over the server’s resources. These files make appealing targets for the malicious user. If these files can be modified or exploited, the web server can be compromised. These files must be monitored by a security tool that reports unauthorized changes to these files.'
  desc 'check', 'CGI or equivalent files must be monitored by a security tool that reports unauthorized changes. It is the purpose of such software to monitor key files for unauthorized changes to them. 

The reviewer should query the ISSO, the SA, and the web administrator and verify the information provided by asking to see the template file or configuration file of the software being used to accomplish this security task.

Example file extensions for files considered to provide active content are, but not limited to: .cgi, .asp, .aspx, .class, .vb, .php, .pl, and .c.

If the site does not have a process in place to monitor changes to CGI program files, this is a finding.'
  desc 'fix', 'Use a monitoring tool to monitor changes to the CGI or equivalent directory. This can be done with something as simple as a script or batch file that would identify a change in the file.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33757r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2271'
  tag rid: 'SV-33089r2_rule'
  tag stig_id: 'WG440 W22'
  tag gtitle: 'WG440'
  tag fix_id: 'F-29393r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
