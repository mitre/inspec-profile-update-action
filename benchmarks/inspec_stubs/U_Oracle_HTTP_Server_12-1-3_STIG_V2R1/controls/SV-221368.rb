control 'SV-221368' do
  title 'OHS must have the cgi-bin directory disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive at the OHS server and virtual host configuration scopes.

3. If the directive and any directives that it contains exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive at the OHS server and virtual host configuration scopes.

3. Comment out the "<Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/cgi-bin">" directive and any directives it contains if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23083r414787_chk'
  tag severity: 'medium'
  tag gid: 'V-221368'
  tag rid: 'SV-221368r414789_rule'
  tag stig_id: 'OH12-1X-000121'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23072r414788_fix'
  tag 'documentable'
  tag legacy: ['SV-78789', 'V-64299']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
