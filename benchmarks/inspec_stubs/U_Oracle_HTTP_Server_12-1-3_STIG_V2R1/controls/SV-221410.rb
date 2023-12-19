control 'SV-221410' do
  title 'OHS must have the ScriptSock directive within a IfModule cgid_module directive disabled.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptSock" directive within a "<IfModule cgid_module>" directive at the OHS server configuration scope.

3. If the directive and its surrounding "<IfModule cgid_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptSock" directive within a "<IfModule cgid_module>" directive at the OHS server configuration scope.

3. Comment out the "ScriptSock" directive and its surrounding "<IfModule cgid_module>" directive if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23125r414913_chk'
  tag severity: 'medium'
  tag gid: 'V-221410'
  tag rid: 'SV-221410r414915_rule'
  tag stig_id: 'OH12-1X-000166'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-23114r414914_fix'
  tag 'documentable'
  tag legacy: ['SV-78885', 'V-64395']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
