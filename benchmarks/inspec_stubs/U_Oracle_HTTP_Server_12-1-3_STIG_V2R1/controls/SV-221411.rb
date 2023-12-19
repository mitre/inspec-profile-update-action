control 'SV-221411' do
  title 'OHS must have the cgi-bin directory disabled.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive at the OHS server and virtual host configuration scopes.

3. If the directive and any directives that it contains exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive at the OHS server and virtual host configuration scopes.

3. Comment out the "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive and any directives it contains if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23126r810867_chk'
  tag severity: 'medium'
  tag gid: 'V-221411'
  tag rid: 'SV-221411r810869_rule'
  tag stig_id: 'OH12-1X-000167'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-23115r810868_fix'
  tag 'documentable'
  tag legacy: ['SV-78887', 'V-64397']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
