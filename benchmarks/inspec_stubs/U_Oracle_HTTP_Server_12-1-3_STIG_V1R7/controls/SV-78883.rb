control 'SV-78883' do
  title 'OHS must have the ScriptAlias /cgi-bin/ directive within a IfModule alias_module directive disabled.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptAlias /cgi-bin/" directive within a "<IfModule alias_module>" directive at the OHS server configuration scope.

3. If the directive and its surrounding "<IfModule alias_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "ScriptAlias /cgi-bin/" directive within a "<IfModule alias_module>" directive at the OHS server configuration scope.

3. Comment out the "ScriptAlias /cgi-bin/" directive and its surrounding "<IfModule alias_module>" directive if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64393'
  tag rid: 'SV-78883r1_rule'
  tag stig_id: 'OH12-1X-000165'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-70323r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
