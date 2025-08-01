control 'SV-32763' do
  title 'All interactive programs must be placed in a designated directory with appropriate permissions.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories.  The Options directive controls which server features are available in a particular directory. The ExecCGI option controls the execution of CGI scripts using mod_cgi.  This needs to be restricted to only the directory intended for script execution.'
  desc 'check', 'Search for the unnecessary CGI programs which may be found in the directories configured with ScriptAlias, Script or other Script* directives. Often, CGI directories are named cgi-bin. Also, CGI AddHandler or SetHandler directives may also be in use for specific handlers such as perl, python and PHP.

To search the http.conf file for Options enter the following command:

grep "Options" /usr/local/apache2/conf/httpd.conf.
For every instance of “Options” in the httpd.conf file other than where CGI files are specifically located, the “ExecCGI” must be explicitly disabled (-ExecCGI).

If the value for Options is not returned with a “-ExecCGI” , this is a finding.'
  desc 'fix', 'Locate any cgi-bin files and directories enabled in the Apache configuration via Script, ScriptAlias or other Script* directives.

Remove the printenv default CGI in cgi-bin directory if it is installed. 

rm $APACHE_PREFIX/cgi-bin/printenv. 

Remove the test-cgi file from the cgi-bin directory if it is installed. 

rm $APACHE_PREFIX/cgi-bin/test-cgi. 

Review and remove any other cgi-bin files which are not needed for business purposes.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33613r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13731'
  tag rid: 'SV-32763r2_rule'
  tag stig_id: 'WA000-WWA050 A22'
  tag gtitle: 'WA000-WWA050'
  tag fix_id: 'F-29240r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
