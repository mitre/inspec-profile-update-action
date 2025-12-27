control 'SV-221360' do
  title 'OHS must have the DirectoryIndex directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "DirectoryIndex" directive.

2. Search for the "DirectoryIndex" directive at the OHS server, virtual host, and directory configuration scopes.

3. If the directive and any surrounding "<IfModule dir_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "DirectoryIndex" directive.

2. Search for the "DirectoryIndex" directive at the OHS server, virtual host, and directory configuration scopes.

3. Comment out the "DirectoryIndex" directive and any surrounding "<IfModule dir_module>" directive if they exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23075r414763_chk'
  tag severity: 'low'
  tag gid: 'V-221360'
  tag rid: 'SV-221360r414765_rule'
  tag stig_id: 'OH12-1X-000113'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23064r414764_fix'
  tag 'documentable'
  tag legacy: ['SV-78773', 'V-64283']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
