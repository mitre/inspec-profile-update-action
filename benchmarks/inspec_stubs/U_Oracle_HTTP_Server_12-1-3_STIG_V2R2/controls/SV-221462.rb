control 'SV-221462' do
  title 'Symbolic links must not be used in the web content directory tree.'
  desc 'A symbolic link allows a file or a directory to be referenced using a symbolic name raising a potential hazard if symbolic linkage is made to a sensitive area. When web scripts are executed and symbolic links are allowed, the web user could be allowed to access locations on the web server that are outside the scope of the web document root or home directory.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Within the directory specified by each "DocumentRoot" directive, check recursively for any symbolic links (e.g., find . -type l -exec ls -ald {} \\;).

4. If any symbolic links are found, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Within the directory specified by each "DocumentRoot" directive, check recursively for any symbolic links (e.g., find . -type l -exec ls -ald {} \\;).

4. Remove any symbolic links found in the "DocumentRoot" directory tree.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23177r415069_chk'
  tag severity: 'high'
  tag gid: 'V-221462'
  tag rid: 'SV-221462r879887_rule'
  tag stig_id: 'OH12-1X-000225'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23166r415070_fix'
  tag 'documentable'
  tag legacy: ['SV-79177', 'V-64687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
