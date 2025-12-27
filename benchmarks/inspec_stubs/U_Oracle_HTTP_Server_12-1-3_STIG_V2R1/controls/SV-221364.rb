control 'SV-221364' do
  title 'OHS must have the IfModule cgid_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<IfModule cgid_module>" directive.

2. Search for the "<IfModule cgid_module>" directive at the OHS server, virtual host, and directory configuration scope.

3. If the directive and any directives that it may contain exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<IfModule cgid_module>" directive.

2. Search for the "<IfModule cgid_module>" directive at the OHS server, virtual host, and directory configuration scopes.

3. Comment out the "<IfModule cgid_module>" directive and any directives it may contain.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23079r414775_chk'
  tag severity: 'low'
  tag gid: 'V-221364'
  tag rid: 'SV-221364r414777_rule'
  tag stig_id: 'OH12-1X-000117'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23068r414776_fix'
  tag 'documentable'
  tag legacy: ['SV-78781', 'V-64291']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
