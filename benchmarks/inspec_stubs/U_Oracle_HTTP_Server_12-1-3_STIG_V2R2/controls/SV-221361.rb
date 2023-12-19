control 'SV-221361' do
  title 'OHS must have the LoadModule cgi_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgi_module" directive within the "<IfModule mpm_prefork_module>" directive at the OHS server configuration scope.

3. If the directive and its surrounding "<IfModule mpm_prefork_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgi_module" directive within the "<IfModule mpm_prefork_module>" directive at the OHS server configuration scope.

3. Comment out the "LoadModule cgi_module" directive and surrounding "<IfModule mpm_prefork_module>" directives if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23076r414766_chk'
  tag severity: 'medium'
  tag gid: 'V-221361'
  tag rid: 'SV-221361r879587_rule'
  tag stig_id: 'OH12-1X-000114'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23065r414767_fix'
  tag 'documentable'
  tag legacy: ['SV-78775', 'V-64285']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
