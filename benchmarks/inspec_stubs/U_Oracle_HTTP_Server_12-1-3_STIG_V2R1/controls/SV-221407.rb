control 'SV-221407' do
  title 'OHS must have the IfModule cgid_module directive disabled for the OHS server, virtual host, and directory configuration.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<IfModule cgid_module>" directive.

2. Search for the "<IfModule cgid_module>" directive at the OHS server, virtual host, and directory configuration scope.

3. If the directive and any directives that it may contain exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<IfModule cgid_module>" directive.

2. Search for the "<IfModule cgid_module>" directive at the OHS server, virtual host, and directory configuration scopes.

3. Comment out the "<IfModule cgid_module>" directive and any directives it may contain.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23122r414904_chk'
  tag severity: 'medium'
  tag gid: 'V-221407'
  tag rid: 'SV-221407r414906_rule'
  tag stig_id: 'OH12-1X-000163'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-23111r414905_fix'
  tag 'documentable'
  tag legacy: ['SV-78879', 'V-64389']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
