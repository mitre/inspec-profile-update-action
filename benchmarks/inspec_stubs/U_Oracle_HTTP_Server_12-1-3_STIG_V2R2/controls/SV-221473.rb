control 'SV-221473' do
  title 'If mod_plsql is not in use with OHS, OHS must have the include moduleconf/* directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', 'If not using mod_plsql:

1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "include moduleconf/*" directive at the OHS server configuration scope.

Note: The complete line may be "include moduleconf/*.conf*".

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "include moduleconf/*" directive at the OHS server configuration scope.

Note: The complete line may be "include moduleconf/*.conf*".

3. Comment out the "include moduleconf/*" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23188r415102_chk'
  tag severity: 'medium'
  tag gid: 'V-221473'
  tag rid: 'SV-221473r879587_rule'
  tag stig_id: 'OH12-1X-000236'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23177r415103_fix'
  tag 'documentable'
  tag legacy: ['SV-78849', 'V-64359']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
