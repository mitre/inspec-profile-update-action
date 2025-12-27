control 'SV-78881' do
  title 'OHS must have the LoadModule cgi_module directive disabled within the IfModule mpm_winnt_module directive.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgi_module" directive within the "<IfModule mpm_winnt_module>" directive at the OHS server configuration scope.

3. If the directive and its surrounding "<IfModule mpm_winnt_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgi_module" directive within the "<IfModule mpm_winnt_module>" directive at the OHS server configuration scope.

3. Comment out the "LoadModule cgi_module" directive and surrounding "<IfModule mpm_winnt_module>" directives if they exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65143r1_chk'
  tag severity: 'low'
  tag gid: 'V-64391'
  tag rid: 'SV-78881r1_rule'
  tag stig_id: 'OH12-1X-000164'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-70321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
