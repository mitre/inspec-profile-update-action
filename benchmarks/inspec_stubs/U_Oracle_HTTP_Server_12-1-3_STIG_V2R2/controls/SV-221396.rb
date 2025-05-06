control 'SV-221396' do
  title 'OHS must have the IfModule mpm_winnt_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "<IfModule mpm_winnt_module>" directive at the OHS server configuration scope.

3. If the directive and any directives it contains exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "<IfModule mpm_winnt_module>" directive at the OHS server configuration scope.

3. Comment out the "<IfModule mpm_winnt_module>" directive and any directives it contains if they exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23111r414871_chk'
  tag severity: 'low'
  tag gid: 'V-221396'
  tag rid: 'SV-221396r879587_rule'
  tag stig_id: 'OH12-1X-000149'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23100r414872_fix'
  tag 'documentable'
  tag legacy: ['SV-78845', 'V-64355']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
