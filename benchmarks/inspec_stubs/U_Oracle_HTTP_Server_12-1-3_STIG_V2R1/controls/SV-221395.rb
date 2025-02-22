control 'SV-221395' do
  title 'OHS must have the path to the icons directory disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "<Directory "${PRODUCT_HOME}/icons">" directive at the OHS server configuration scope.

3. If the directive exists and any directives that it contains are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "<Directory "${PRODUCT_HOME}/icons">" directive at the OHS server configuration scope.

3. Comment out the "<Directory "$PRODUCT_HOME}/icons">" directive and any directives that it contains if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23110r414868_chk'
  tag severity: 'medium'
  tag gid: 'V-221395'
  tag rid: 'SV-221395r414870_rule'
  tag stig_id: 'OH12-1X-000148'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23099r414869_fix'
  tag 'documentable'
  tag legacy: ['SV-78843', 'V-64353']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
