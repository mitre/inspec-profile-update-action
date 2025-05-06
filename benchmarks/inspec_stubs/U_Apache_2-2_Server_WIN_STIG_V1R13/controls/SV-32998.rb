control 'SV-32998' do
  title 'All interactive programs must be placed in a designated directory with appropriate permissions.'
  desc 'CGI scripts are one of the most exploited vulnerabilities on web servers.  CGI script execution in Apache can be accomplished via two methods.  The first method uses the ScriptAlias directive to tell the server everything in that directory is a CGI script.  The second method uses a combination of the Options directive and AddHandler or SetHandler directives.  For situations where the combination of the Options directive and Handler directives are used, the ability to centrally manage scripts is lost, creating vulnerability on the web server.  It is best to manage scripts using the ScriptAlias directive.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives:  SetHandler, AddHandler, and Options.

For all occurrences of the SetHandler and AddHandler directives query the Web Administrator to determine if the directives are allowing CGI scripts to be used. 

If CGI Scripts are used via the SetHandler or AddHandler directives, this is a finding.

For all occurrences of the Options directive that are using +ExecCGI or ExecCGI, this is a finding. 

If the Options directive is found with -ExecCGI, this is not a finding. 

If the value does not exist, this would be a finding unless the Options statement is set to “None”.'
  desc 'fix', 'Locate the scripts in a ScriptAlias directory, and/or add the appropriate symbol to explicitly disable ExecCGI, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13731'
  tag rid: 'SV-32998r1_rule'
  tag stig_id: 'WA000-WWA050 W22'
  tag gtitle: 'WA000-WWA050'
  tag fix_id: 'F-29302r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
