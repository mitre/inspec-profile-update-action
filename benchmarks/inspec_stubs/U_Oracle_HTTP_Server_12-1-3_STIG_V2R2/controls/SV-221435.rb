control 'SV-221435' do
  title 'The OHS instance configuration must not reference directories that contain an .htaccess file.'
  desc '.htaccess files are used to override settings in the OHS configuration files.  The placement of the .htaccess file is also important as the settings will affect the directory where the file is located and any subdirectories below.  Allowing the use of .htaccess files, the hosted application security posture and overall OHS posture could change dependent on the URL being accessed.  Allowing the override of parameters in .htaccess files makes it difficult to truly know the security posture of the system and it also makes it difficult to understand what the security posture may have been if an attack is successful.  To thwart the overriding of parameters, .htaccess files must not be used and the "AllowOverride" parameter must be set to "none".'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directives at the server and virtual host configuration scopes.

3. Go to the location specified as the value for each "<Directory>" directive (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs).

4. Check for the existence of any .htaccess files in the aforementioned locations (e.g., find . -name .htaccess -print).

5. If any .htaccess files are found, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directives at the server and virtual host configuration scopes.

3. Go to the location specified as the value for each "<Directory>" directive (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs).

4. find . -name .htaccess -exec rm {} \\;'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23150r414988_chk'
  tag severity: 'medium'
  tag gid: 'V-221435'
  tag rid: 'SV-221435r879887_rule'
  tag stig_id: 'OH12-1X-000197'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23139r414989_fix'
  tag 'documentable'
  tag legacy: ['SV-79123', 'V-64633']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
