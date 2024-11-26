control 'SV-221546' do
  title 'OHS must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.'
  desc "The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end.

Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version."
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "DocumentRoot" directives at the server and virtual host configuration scopes.

3. Go to the location specified as the value for each "DocumentRoot" directive (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs).

4. Check for the existence of any index.html file in the directory specified as the "DocumentRoot" and its subdirectories (e.g., find . -type d, find . -type f -name index.html, cat index.html).

5. If an index.html files is not found or there is content in the file that is irrelevant to the website, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "DocumentRoot" directives at the server and virtual host configuration scopes.

3. Go to the location specified as the value for each "DocumentRoot" directive (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs) and its subdirectories.

4. Create a standard or empty index.html file (e.g., echo > index.html) in the directory specified for "DocumentRoot" and any subdirectories it may have.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23261r415317_chk'
  tag severity: 'low'
  tag gid: 'V-221546'
  tag rid: 'SV-221546r415319_rule'
  tag stig_id: 'OH12-1X-000346'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-23250r415318_fix'
  tag 'documentable'
  tag legacy: ['SV-78967', 'V-64477']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
