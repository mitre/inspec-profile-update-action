control 'SV-214244' do
  title 'The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.'
  desc 'Scripts allow server-side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server.

To ensure scripts are not added to the web server and run maliciously, script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.  

Locate "cgi-bin" files and directories enabled in the Apache configuration via "Script", "ScriptAlias" or "ScriptAliasMatch", and "ScriptInterpreterSource" directives:

# cat /<path_to_file>/httpd.conf | grep -i "Script"

If any scripts are present that are not needed for application operation, this is a finding.

If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Review "Script", "ScriptAlias" or "ScriptAliasMatch", and "ScriptInterpreterSource" directives.

Go into each directory and locate "cgi-bin" files. Remove any script that is not needed for application operation.

Ensure this process is documented and approved by the ISSO.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15458r881425_chk'
  tag severity: 'medium'
  tag gid: 'V-214244'
  tag rid: 'SV-214244r881427_rule'
  tag stig_id: 'AS24-U1-000310'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-15456r881426_fix'
  tag 'documentable'
  tag legacy: ['SV-102743', 'V-92655']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
