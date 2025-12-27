control 'SV-78787' do
  title 'OHS must have the ScriptSock directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptSock" directive within a "<IfModule cgid_module>" directive at the OHS server configuration scope.  Note: “ScriptSock” may appear as “Scriptsock” within the httpd.conf file.

3. If the directive and its surrounding "<IfModule cgid_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptSock" directive within a "<IfModule cgid_module>" directive at the OHS server configuration scope.  Note: “ScriptSock” may appear as “Scriptsock” within the httpd.conf file.

3. Comment out the "ScriptSock" directive and its surrounding "<IfModule cgid_module>" directive if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65049r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64297'
  tag rid: 'SV-78787r1_rule'
  tag stig_id: 'OH12-1X-000120'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-70227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
