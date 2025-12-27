control 'SV-221347' do
  title 'OHS must have the LoadModule status_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule status_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule status_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule status_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23062r414724_chk'
  tag severity: 'medium'
  tag gid: 'V-221347'
  tag rid: 'SV-221347r414726_rule'
  tag stig_id: 'OH12-1X-000100'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23051r414725_fix'
  tag 'documentable'
  tag legacy: ['SV-78747', 'V-64257']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
